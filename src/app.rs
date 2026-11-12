//! The application: its site, its compiled routes, its gate, and the
//! pipeline every request runs.

use std::borrow::Cow;
use std::cell::Cell;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use serve_net::http_net::MethodSet;
use serve_net::{
    Envelope, HttpHead, HttpReply, HttpRequest, HttpService, Method, Outcome, Scheme, Verdict,
    WorkClass,
};

use crate::assets::{self, Assets};
use crate::cors::Cors;
use crate::csrf;
use crate::cx::{Out, is_local_target};
use crate::error::{self, BuildError, Problem};
use crate::headers::SecurityHeaders;
use crate::policy::{CachePolicy, Cacheable, Compression, Served, compressible};
use crate::route::{Access, BoxHandler, Group, Route};
use crate::router::{self, Captures, Trie};
use crate::url::{self, TrailingSlash};
use crate::{
    Context, Denial, DenialKind, ErrorPage, Event, EventKind, Events, Gate, Identity, NoEvents,
    NoRender, Open, Output, Render, Request, RequestId, Result, Stage, TemplateId,
};

/// The default budget for one rendered page.
///
/// ```
/// assert_eq!(web_net::DEFAULT_PAGE_LIMIT, 8 * 1024 * 1024);
/// ```
pub const DEFAULT_PAGE_LIMIT: usize = 8 << 20;

/// A named point in the pipeline where registered code runs, only for the
/// routes it registered for. A route with no hooks pays nothing.
///
/// ```
/// use web_net::{App, Error, Hook, Routes, get};
///
/// // A `Routed` hook runs before the handler; its error ends the request.
/// let app = App::builder()
///     .hook(Hook::Routed, Routes::prefix("/beta"), |_cx| Err(Error::forbidden("beta.closed")))
///     .route(get("/beta/news", |cx| cx.text(200, "news")))
///     .build()?;
/// let r = serve_net::testing::respond(&app, b"GET /beta/news HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.status, 403);
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    /// After the access check passed, before the handler: locale, feature
    /// flags, an A/B variant. An error ends the request.
    Routed,
    /// After the handler succeeded, before the reply leaves: add headers.
    /// An error replaces the reply with the error page.
    Finish,
    /// Inside [`Context::render`], before the engine runs: choose a variant, add
    /// headers. A hook that renders does not run these hooks again.
    BeforeRender,
}

/// Which routes a hook runs for.
///
/// ```
/// use web_net::Routes;
///
/// let every = Routes::all();
/// let blog = Routes::prefix("/blog");
/// let pages = Routes::named(&["home", "about"]);
/// # let _ = (every, blog, pages);
/// ```
#[derive(Clone, Debug)]
pub struct Routes(Selector);

#[derive(Clone, Debug)]
enum Selector {
    All,
    Prefix(String),
    Named(Vec<&'static str>),
}

impl Routes {
    /// Every route.
    ///
    /// ```
    /// use web_net::{App, Hook, Routes, get};
    ///
    /// let app = App::builder()
    ///     .hook(Hook::Finish, Routes::all(), |cx| {
    ///         cx.set_header("x-site", "demo");
    ///         Ok(())
    ///     })
    ///     .route(get("/", |cx| cx.text(200, "home")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("x-site"), Some(&b"demo"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn all() -> Self {
        Self(Selector::All)
    }

    /// Routes whose pattern starts with `prefix` (`/blog`).
    ///
    /// ```
    /// use serve_net::testing::respond;
    /// use web_net::{App, Hook, Routes, get};
    ///
    /// let app = App::builder()
    ///     .hook(Hook::Finish, Routes::prefix("/docs"), |cx| {
    ///         cx.set_header("x-section", "docs");
    ///         Ok(())
    ///     })
    ///     .route(get("/docs/intro", |cx| cx.text(200, "intro")))
    ///     .route(get("/docsearch", |cx| cx.text(200, "search")))
    ///     .build()?;
    /// let r = respond(&app, b"GET /docs/intro HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("x-section"), Some(&b"docs"[..]));
    /// // A prefix matches whole segments.
    /// let r = respond(&app, b"GET /docsearch HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("x-section"), None);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn prefix(prefix: impl Into<String>) -> Self {
        Self(Selector::Prefix(prefix.into()))
    }

    /// Routes with one of these names.
    ///
    /// ```
    /// use web_net::{App, Hook, Routes, get};
    ///
    /// let app = App::builder()
    ///     .hook(Hook::Finish, Routes::named(&["home", "about"]), |cx| {
    ///         cx.set_header("x-page", "static");
    ///         Ok(())
    ///     })
    ///     .route(get("/", |cx| cx.text(200, "home")).name("home"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("x-page"), Some(&b"static"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn named(names: &[&'static str]) -> Self {
        Self(Selector::Named(names.to_vec()))
    }

    fn matches(&self, pattern: &str, name: Option<&str>) -> bool {
        match &self.0 {
            Selector::All => true,
            Selector::Prefix(p) => {
                let p = p.trim_end_matches('/');
                pattern == p
                    || pattern
                        .strip_prefix(p)
                        .is_some_and(|rest| rest.starts_with('/'))
            }
            Selector::Named(names) => name.is_some_and(|n| names.contains(&n)),
        }
    }
}

pub(crate) type HookFn<I, E> = Arc<dyn Fn(&mut Context<'_, I, E>) -> Result + Send + Sync>;

/// What [`App::classify`] tells a dispatcher before admission.
///
/// ```
/// use web_net::{App, get};
/// use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};
///
/// // A dispatcher in front of the app that answers with what `classify` said.
/// struct Probe(App);
/// impl HttpService for Probe {
///     fn call(&self, req: &HttpRequest<'_>, _: &Envelope, reply: &mut HttpReply) -> Outcome {
///         let c = self.0.classify(req.head());
///         reply.text(200, &format!("{:?} {:?}", c.route, c.work));
///         Outcome::Done
///     }
/// }
///
/// let app = App::builder().route(get("/", |cx| cx.text(200, "hi"))).build()?;
/// let r = serve_net::testing::respond(&Probe(app), b"GET /none HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.text(), "None Quick");
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Classified {
    /// The route that will run, if one matched.
    pub route: Option<RouteId>,
    /// How its handler behaves (`Quick` when nothing matched).
    pub work: WorkClass,
}

/// A declared route (one method of one pattern), numbered in declaration
/// order.
///
/// ```
/// use web_net::{App, get};
/// use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};
///
/// // A dispatcher in front of the app that answers with what `classify` said.
/// struct Probe(App);
/// impl HttpService for Probe {
///     fn call(&self, req: &HttpRequest<'_>, _: &Envelope, reply: &mut HttpReply) -> Outcome {
///         let c = self.0.classify(req.head());
///         reply.text(200, &format!("{:?} {:?}", c.route, c.work));
///         Outcome::Done
///     }
/// }
///
/// let app = App::builder()
///     .route(get("/", |cx| cx.text(200, "home")))
///     .route(get("/about", |cx| cx.text(200, "about")))
///     .build()?;
/// let r = serve_net::testing::respond(&Probe(app), b"GET /about HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.text(), "Some(RouteId(1)) Quick");
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RouteId(pub u32);

/// The parts of the application every handler can reach.
pub(crate) struct Shared<E: Render> {
    pub(crate) render: Option<E>,
    pub(crate) checkpoint: Option<Box<dyn crate::Checkpoint>>,
    pub(crate) events: Box<dyn Events>,
    pub(crate) page_limit: usize,
    pub(crate) base: Box<str>,
    sign_in: Option<Box<str>>,
    challenge: Box<str>,
    wipe: bool,
    security: SecurityHeaders,
    pub(crate) csrf: Option<csrf_sec::Csrf>,
    pub(crate) redirect_hosts: Vec<Box<str>>,
    compression: Option<Compression>,
}

/// Where a reply is going: the request's envelope, and whether security
/// headers for HTTPS apply (HTTPS, and not a development host).
#[derive(Clone, Copy)]
pub(crate) struct At<'a> {
    pub(crate) env: &'a Envelope,
    pub(crate) tls: bool,
    /// The client prefers JSON to HTML: error replies are JSON.
    pub(crate) json: bool,
}

type ReadyFn = Arc<dyn Fn() -> bool + Send + Sync>;

#[derive(Clone)]
enum Health {
    Live,
    Ready(ReadyFn),
}

#[derive(Clone, Debug, Default)]
struct Site {
    /// Lower case; the first is canonical.
    hosts: Vec<Box<str>>,
    aliases: Vec<Box<str>>,
    development: bool,
    /// Any `Host` is the site (`Builder::any_host`); without it and without
    /// declared hosts, only development hosts are.
    any_host: bool,
    slash: TrailingSlash,
    lowercase: bool,
    https_only: bool,
}

struct Entry<G: Gate, E: Render> {
    handler: BoxHandler<G::Identity, E>,
    access: Access<G::Rule>,
    names: Box<[Box<str>]>,
    pattern: Box<str>,
    work: WorkClass,
    template: Option<TemplateId>,
    csrf: bool,
    limits: form_net::Limits,
    cors: Option<Arc<Cors>>,
    cache: CachePolicy,
    /// `Cache-Control` for guests and for signed-in visitors, made once.
    cache_values: (Option<Box<str>>, Option<Box<str>>),
    routed: Box<[HookFn<G::Identity, E>]>,
    finish: Box<[HookFn<G::Identity, E>]>,
    before_render: Box<[HookFn<G::Identity, E>]>,
}

struct Endpoint {
    /// Entry per method, by `Method::index`.
    methods: [Option<u32>; 10],
    allow: Box<str>,
    set: MethodSet,
}

/// A web application: one site, its routes, and its gate. Built once at
/// start-up with [`App::builder`] or [`App::with_gate`]; immutable after.
///
/// [`listen`](Self::listen) serves it on an address. It is also a
/// `serve_net::HttpService`, so it runs on any serve-net server as it is,
/// and [`respond`](Self::respond) runs it from a wrapper's own service.
///
/// ```
/// use web_net::{App, get};
///
/// let app = App::builder()
///     .route(get("/", |cx| cx.html(200, "<h1>Hello</h1>")))
///     .route(get("/users/:id", |cx| {
///         let id: u64 = cx.param_as("id")?;
///         cx.text(200, &format!("user {id}"))
///     }))
///     .build()?;
///
/// let reply = serve_net::testing::respond(&app, b"GET /users/7 HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!((reply.status, reply.text()), (200, "user 7"));
///
/// let reply = serve_net::testing::respond(&app, b"GET /users/7/ HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(reply.status, 301);
/// assert_eq!(reply.header("location"), Some(&b"/users/7"[..]));
/// # Ok::<(), web_net::BuildError>(())
/// ```
pub struct App<G: Gate = Open, E: Render = NoRender> {
    gate: G,
    shared: Shared<E>,
    site: Site,
    trie: Trie,
    endpoints: Vec<Endpoint>,
    entries: Vec<Entry<G, E>>,
    allow_all: Box<str>,
    assets: Vec<Assets>,
    health: Vec<(Box<str>, Health)>,
    streams: assets::Streams,
}

impl App<Open> {
    /// A builder with the [`Open`] gate: every visitor is a guest and every
    /// route is public, so routes declare no access.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder().route(get("/", |cx| cx.text(200, "hi"))).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!((r.status, r.text()), (200, "hi"));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn builder() -> Builder<Open> {
        Builder::new(Open)
    }
}

impl<G: Gate> App<G> {
    /// A builder with `gate` for authentication and authorization. Every
    /// route then declares its access, [`public`](crate::Route::public) or
    /// [`allow(rule)`](crate::Route::allow), or the build fails.
    ///
    /// ```
    /// use serve_net::testing::respond;
    /// use web_net::{App, Denial, Gate, Guest, Request, get};
    ///
    /// enum Rule { Staff }
    /// struct NoStaff;
    /// impl Gate for NoStaff {
    ///     type Identity = Guest;
    ///     type Rule = Rule;
    ///     fn authenticate(&self, _: &Request<'_>) -> Result<Guest, Denial> { Ok(Guest) }
    ///     fn authorize(&self, _: &Guest, _: &Rule, _: &Request<'_>) -> Result<(), Denial> {
    ///         Err(Denial::forbidden("staff.only"))
    ///     }
    /// }
    ///
    /// // A route that declares no access stops the build.
    /// assert!(App::with_gate(NoStaff).route(get("/", |cx| cx.text(200, "hi"))).build().is_err());
    ///
    /// let app = App::with_gate(NoStaff)
    ///     .route(get("/", |cx| cx.text(200, "hi")).public())
    ///     .route(get("/admin", |cx| cx.text(200, "admin")).allow(Rule::Staff))
    ///     .build()?;
    /// assert_eq!(respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").status, 200);
    /// assert_eq!(respond(&app, b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n").status, 403);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn with_gate(gate: G) -> Builder<G> {
        Builder::new(gate)
    }
}

/// Declares an application. Every mistake is reported by
/// [`build`](Self::build) at once, before anything listens.
///
/// ```
/// use web_net::{App, get};
///
/// let app = App::builder()
///     .host("example.com")
///     .development()
///     .health("/healthz")
///     .route(get("/", |cx| cx.text(200, "home")))
///     .build()?;
/// let r = serve_net::testing::respond(&app, b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.text(), "ok");
/// # Ok::<(), web_net::BuildError>(())
/// ```
pub struct Builder<G: Gate, E: Render = NoRender> {
    gate: G,
    routes: Vec<Route<G::Identity, G::Rule, E>>,
    hooks: Vec<(Hook, Routes, HookFn<G::Identity, E>)>,
    site: Site,
    base: String,
    render: Option<E>,
    checkpoint: Option<Box<dyn crate::Checkpoint>>,
    events: Box<dyn Events>,
    page_limit: usize,
    sign_in: Option<String>,
    challenge: String,
    wipe: bool,
    security: SecurityHeaders,
    assets: Vec<Assets>,
    health: Vec<(String, Health)>,
    csrf: Option<csrf_sec::Csrf>,
    redirect_hosts: Vec<Box<str>>,
    compression: Option<Compression>,
    /// Problems found before `build` (an engine set after routes).
    early: Vec<Problem>,
}

impl<G: Gate, E: Render> Builder<G, E> {
    fn new(gate: G) -> Self {
        Self {
            gate,
            routes: Vec::new(),
            hooks: Vec::new(),
            site: Site::default(),
            base: String::new(),
            render: None,
            checkpoint: None,
            events: Box::new(NoEvents),
            page_limit: DEFAULT_PAGE_LIMIT,
            sign_in: None,
            challenge: "Session".into(),
            wipe: false,
            security: SecurityHeaders::default(),
            assets: Vec::new(),
            health: Vec::new(),
            csrf: None,
            redirect_hosts: Vec::new(),
            compression: None,
            early: Vec::new(),
        }
    }

    /// Compress replies with gzip when the client accepts it: HTML, CSS,
    /// JavaScript, JSON, XML, SVG, and other text, over a minimum size. Off
    /// by default: a proxy in front usually compresses.
    ///
    /// A compressed page that carries a secret beside text the visitor
    /// chose (a reflected query value) can leak the secret through its
    /// compressed size (BREACH). csrf-sec masks its tokens per reply; keep
    /// compression off for pages with other secrets.
    ///
    /// ```
    /// use web_net::{App, Compression, get};
    ///
    /// let app = App::builder()
    ///     .compress(Compression::default())
    ///     .route(get("/", |cx| cx.text(200, &"hello ".repeat(400))))
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\n\r\n",
    /// );
    /// assert_eq!(r.header("content-encoding"), Some(&b"gzip"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn compress(mut self, compression: Compression) -> Self {
        self.compression = Some(compression);
        self
    }

    /// CSRF protection with csrf-sec (re-exported as
    /// [`web_net::csrf_sec`](crate::csrf_sec)), built from a persisted
    /// 32-byte key. Required as soon as one route takes an unsafe method and
    /// is not [exempt](crate::Route::csrf_exempt).
    ///
    /// web-net always applies the origin policy and a token, whatever the
    /// `Csrf`'s `Mode`; its keys, lifetimes, and allowed origins apply as set.
    ///
    /// ```
    /// use web_net::{App, csrf_sec::Csrf, get, post};
    ///
    /// let app = App::builder()
    ///     .csrf(Csrf::new(*b"a persisted 32-byte secret key!!").unwrap())
    ///     .route(get("/", |cx| cx.text(200, "form")))
    ///     .route(post("/", |cx| cx.redirect(303, "/")))
    ///     .build()?;
    /// // A POST without a token is refused before its handler runs.
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    /// );
    /// assert_eq!(r.status, 403);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn csrf(mut self, csrf: csrf_sec::Csrf) -> Self {
        self.csrf = Some(csrf);
        self
    }

    /// Hosts that [`Context::redirect_external`] may send a visitor to
    /// (`accounts.example.com`). Everything else is refused.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .redirect_hosts(&["accounts.example.com"])
    ///     .route(get("/login", |cx| cx.redirect_external(302, "https://accounts.example.com/login")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /login HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("location"), Some(&b"https://accounts.example.com/login"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn redirect_hosts(mut self, hosts: &[&str]) -> Self {
        self.redirect_hosts.extend(
            hosts
                .iter()
                .map(|h| h.to_ascii_lowercase().into_boxed_str()),
        );
        self
    }

    /// Serves a folder of files under a mount path, before routing and
    /// without the gate (files are public).
    ///
    /// ```
    /// use web_net::{App, Assets};
    ///
    /// let dir = std::env::temp_dir().join("web-net-doc-builder-assets");
    /// std::fs::create_dir_all(&dir).unwrap();
    /// std::fs::write(dir.join("hello.txt"), "hello").unwrap();
    ///
    /// let app = App::builder().assets(Assets::new("/static", &dir)).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /static/hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!((r.status, r.text()), (200, "hello"));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn assets(mut self, assets: Assets) -> Self {
        self.assets.push(assets);
        self
    }

    /// A liveness path (`/healthz`): `200 ok` whenever the process answers.
    /// Answered before routing and without the gate.
    ///
    /// ```
    /// let app = web_net::App::builder().health("/healthz").build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!((r.status, r.text()), (200, "ok"));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn health(mut self, path: &str) -> Self {
        self.health.push((path.to_owned(), Health::Live));
        self
    }

    /// A readiness path (`/readyz`): `200 ready` when `check` says so,
    /// `503 not ready` otherwise. Keep `check` to a flag read: it runs on the
    /// request path.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use std::sync::atomic::{AtomicBool, Ordering};
    /// use serve_net::testing::respond;
    ///
    /// let up = Arc::new(AtomicBool::new(false));
    /// let flag = Arc::clone(&up);
    /// let app = web_net::App::builder()
    ///     .ready("/readyz", move || flag.load(Ordering::Relaxed))
    ///     .build()?;
    /// let req = b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n";
    /// assert_eq!(respond(&app, req).status, 503);
    /// up.store(true, Ordering::Relaxed);
    /// assert_eq!(respond(&app, req).text(), "ready");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn ready(mut self, path: &str, check: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        self.health
            .push((path.to_owned(), Health::Ready(Arc::new(check))));
        self
    }

    /// The security headers every reply carries (default
    /// [`SecurityHeaders::default`]).
    ///
    /// ```
    /// use web_net::{App, SecurityHeaders, get};
    ///
    /// // A proxy in front sets the security headers, so web-net sends none.
    /// let app = App::builder()
    ///     .security_headers(SecurityHeaders::none())
    ///     .route(get("/", |cx| cx.html(200, "<p>hi</p>")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("content-security-policy"), None);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn security_headers(mut self, policy: SecurityHeaders) -> Self {
        self.security = policy;
        self
    }

    /// Adds a route.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder().route(get("/about", |cx| cx.text(200, "about"))).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /about HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "about");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn route(mut self, route: Route<G::Identity, G::Rule, E>) -> Self {
        self.routes.push(route);
        self
    }

    /// Adds a group's routes.
    ///
    /// ```
    /// use web_net::{App, Group, get};
    ///
    /// let app = App::builder()
    ///     .group(Group::at("/admin").route(get("/users", |cx| cx.text(200, "users"))))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /admin/users HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "users");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn group(mut self, group: Group<G::Identity, G::Rule, E>) -> Self {
        self.routes.extend(group.into_routes());
        self
    }

    /// Runs `f` at `hook` for the routes `routes` selects.
    ///
    /// ```
    /// use web_net::{App, Hook, Routes, get};
    ///
    /// let app = App::builder()
    ///     .hook(Hook::Finish, Routes::all(), |cx| {
    ///         cx.set_header("x-served-by", "web-net");
    ///         Ok(())
    ///     })
    ///     .route(get("/", |cx| cx.text(200, "home")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("x-served-by"), Some(&b"web-net"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn hook<F>(mut self, hook: Hook, routes: Routes, f: F) -> Self
    where
        F: Fn(&mut Context<'_, G::Identity, E>) -> Result + Send + Sync + 'static,
    {
        self.hooks.push((hook, routes, Arc::new(f)));
        self
    }

    /// A host the site answers (`example.com`, or `localhost:8080` with its
    /// port). The first one is canonical; any other host gets 421.
    ///
    /// With no host declared, the site answers the development hosts only
    /// (`localhost`, `127.0.0.1`, `[::1]`, `*.localhost`), so a site works
    /// on a laptop as it is and a name someone else points at the server
    /// (DNS rebinding) is never the site. Declare the production host before
    /// deploying, or [`any_host`](Self::any_host) for a site that must
    /// answer every name.
    ///
    /// ```
    /// use web_net::{App, get};
    /// use serve_net::testing::respond;
    ///
    /// let app = App::builder().route(get("/", |cx| cx.text(200, "hi"))).build()?;
    /// assert_eq!(respond(&app, b"GET / HTTP/1.1\r\nHost: localhost:8080\r\n\r\n").status, 200);
    /// assert_eq!(respond(&app, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").status, 421);
    ///
    /// let app = App::builder().host("example.com").route(get("/", |cx| cx.text(200, "hi"))).build()?;
    /// assert_eq!(respond(&app, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").status, 200);
    /// assert_eq!(respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").status, 421);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn host(mut self, host: &str) -> Self {
        self.site.hosts.push(host.to_ascii_lowercase().into());
        self
    }

    /// A host that is redirected (301, or 308 for unsafe methods) to the
    /// canonical host (`www.example.com` to `example.com`).
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .host("example.com")
    ///     .alias("www.example.com")
    ///     .route(get("/", |cx| cx.text(200, "home")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
    /// assert_eq!((r.status, r.header("location")), (301, Some(&b"http://example.com/"[..])));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn alias(mut self, host: &str) -> Self {
        self.site.aliases.push(host.to_ascii_lowercase().into());
        self
    }

    /// A development instance of a site with declared hosts: `localhost`,
    /// `127.0.0.1`, `[::1]`, and `*.localhost` are answered as the site too
    /// (with any port), and HTTPS is not required for them. Never set this
    /// in production. (A site with no declared host answers only these
    /// already.)
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .host("example.com")
    ///     .development()
    ///     .route(get("/", |cx| cx.text(200, "home")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost:8080\r\n\r\n");
    /// assert_eq!(r.status, 200);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn development(mut self) -> Self {
        self.site.development = true;
        self
    }

    /// Answers every `Host`, for a site behind a front that checked the
    /// host already, or one that is reached by names it cannot list. Not
    /// with [`host`](Self::host).
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder().any_host().route(get("/", |cx| cx.text(200, "hi"))).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: anything.example\r\n\r\n");
    /// assert_eq!(r.status, 200);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn any_host(mut self) -> Self {
        self.site.any_host = true;
        self
    }

    /// The path the site is installed under (`/blog`). It is removed before
    /// routing and added back by [`Context::url`], so routes and links are written
    /// as if the site were at `/`. Requests outside it get 404.
    ///
    /// ```
    /// use serve_net::testing::respond;
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .base("/blog")
    ///     .route(get("/posts", |cx| cx.text(200, "posts")))
    ///     .build()?;
    /// assert_eq!(respond(&app, b"GET /blog/posts HTTP/1.1\r\nHost: localhost\r\n\r\n").text(), "posts");
    /// assert_eq!(respond(&app, b"GET /posts HTTP/1.1\r\nHost: localhost\r\n\r\n").status, 404);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn base(mut self, base: &str) -> Self {
        self.base = base.to_owned();
        self
    }

    /// The trailing-slash policy (default [`TrailingSlash::Strip`]).
    ///
    /// ```
    /// use web_net::{App, TrailingSlash, get};
    ///
    /// // Both spellings reach the route and neither is redirected.
    /// let app = App::builder()
    ///     .trailing_slash(TrailingSlash::Ignore)
    ///     .route(get("/docs", |cx| cx.text(200, "docs")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /docs/ HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!((r.status, r.text()), (200, "docs"));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn trailing_slash(mut self, policy: TrailingSlash) -> Self {
        self.site.slash = policy;
        self
    }

    /// Paths are lower case: one with an upper-case letter is redirected.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .lowercase_paths()
    ///     .route(get("/about", |cx| cx.text(200, "about")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /About HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!((r.status, r.header("location")), (301, Some(&b"/about"[..])));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn lowercase_paths(mut self) -> Self {
        self.site.lowercase = true;
        self
    }

    /// Plain HTTP is redirected to HTTPS on the canonical host (behind a
    /// TLS proxy, serve-net must trust the proxy's scheme). Needs a host.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .host("example.com")
    ///     .https_only()
    ///     .route(get("/", |cx| cx.text(200, "home")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    /// assert_eq!((r.status, r.header("location")), (301, Some(&b"https://example.com/"[..])));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn https_only(mut self) -> Self {
        self.site.https_only = true;
        self
    }

    /// The site-relative sign-in page. A [`Denial::sign_in`] on a `GET` or
    /// `HEAD` is then answered with a 303 to it, the page asked for passed
    /// as `next`; without it, or for other methods, the answer is 401.
    ///
    /// ```
    /// use web_net::{App, get};
    /// # use web_net::{Denial, Gate, Guest, Request};
    /// # enum Rule { Member }
    /// # struct Members;
    /// # impl Gate for Members {
    /// #     type Identity = Guest;
    /// #     type Rule = Rule;
    /// #     fn authenticate(&self, _: &Request<'_>) -> Result<Guest, Denial> { Ok(Guest) }
    /// #     fn authorize(&self, _: &Guest, _: &Rule, _: &Request<'_>) -> Result<(), Denial> {
    /// #         Err(Denial::sign_in("session.none"))
    /// #     }
    /// # }
    /// // `Members` answers `Rule::Member` with `Denial::sign_in` for everyone.
    /// let app = App::with_gate(Members)
    ///     .sign_in("/login")
    ///     .route(get("/login", |cx| cx.text(200, "sign in")).public())
    ///     .route(get("/account", |cx| cx.text(200, "account")).allow(Rule::Member))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /account HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!((r.status, r.header("location")), (303, Some(&b"/login?next=/account"[..])));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn sign_in(mut self, path: &str) -> Self {
        self.sign_in = Some(path.to_owned());
        self
    }

    /// The `WWW-Authenticate` value sent with a 401 (default `Session`).
    ///
    /// ```
    /// let app = web_net::App::builder().www_authenticate("Bearer").build()?;
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn www_authenticate(mut self, challenge: &str) -> Self {
        challenge.clone_into(&mut self.challenge);
        self
    }

    /// Where refusals, denials, and failures are reported.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use std::sync::atomic::{AtomicU32, Ordering};
    /// use web_net::{App, Error, Event, EventKind, Events, get};
    ///
    /// #[derive(Default)]
    /// struct Failures(AtomicU32);
    /// impl Events for Failures {
    ///     fn event(&self, e: &Event<'_>) {
    ///         if e.kind == EventKind::Failed {
    ///             self.0.fetch_add(1, Ordering::Relaxed);
    ///         }
    ///     }
    /// }
    ///
    /// let failures = Arc::new(Failures::default());
    /// let app = App::builder()
    ///     .events(Arc::clone(&failures))
    ///     .route(get("/", |_cx| Err(Error::unavailable("db.down"))))
    ///     .build()?;
    /// serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(failures.0.load(Ordering::Relaxed), 1);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn events(mut self, events: impl Events) -> Self {
        self.events = Box::new(events);
        self
    }

    /// The in-flight revocation check at web-net's stages.
    ///
    /// ```
    /// use serve_net::{Envelope, Verdict};
    /// use web_net::{App, Checkpoint, Stage, get};
    ///
    /// struct Maintenance;
    /// impl Checkpoint for Maintenance {
    ///     fn check(&self, _: &Envelope, _: Stage) -> Verdict {
    ///         Verdict::Deny { status: 503 }
    ///     }
    /// }
    ///
    /// let app = App::builder()
    ///     .checkpoint(Maintenance)
    ///     .route(get("/", |cx| cx.text(200, "hi")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.status, 503);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn checkpoint(mut self, checkpoint: impl crate::Checkpoint) -> Self {
        self.checkpoint = Some(Box::new(checkpoint));
        self
    }

    /// The budget for one rendered page (default 8 MiB).
    ///
    /// ```
    /// use web_net::{App, Context, Guest, get};
    /// # use web_net::{Output, Render, RenderError, TemplateId};
    /// # struct Pages;
    /// # impl Render for Pages {
    /// #     type View<'a> = str;
    /// #     fn template(&self, name: &str) -> Option<TemplateId> {
    /// #         (name == "page").then_some(TemplateId(0))
    /// #     }
    /// #     fn render(&self, _: TemplateId, text: &str, out: &mut Output<'_>) -> Result<(), RenderError> {
    /// #         out.write_str(text)
    /// #     }
    /// # }
    /// // `Pages` is an engine whose one template, "page", writes the view (a `str`).
    /// let app = App::builder()
    ///     .render(Pages)
    ///     .page_limit(4)
    ///     .route(get("/", |cx: &mut Context<'_, Guest, Pages>| cx.render("more than four bytes")).template("page"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.status, 500);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn page_limit(mut self, bytes: usize) -> Self {
        self.page_limit = bytes;
        self
    }

    /// Zero the reply buffers web-net reuses after every request, so one
    /// visitor's page never lingers in memory another request reuses. Costs
    /// one pass over the bytes written.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .wipe_buffers()
    ///     .route(get("/", |cx| cx.text(200, "a private page")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "a private page");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn wipe_buffers(mut self) -> Self {
        self.wipe = true;
        self
    }

    /// Compiles the application.
    ///
    /// # Errors
    ///
    /// A [`BuildError`] listing every problem: a route without declared
    /// access, a malformed pattern, two handlers for one method of one
    /// path, an unknown template, a malformed host or base path.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// assert!(App::builder().route(get("/", |cx| cx.text(200, "hi"))).build().is_ok());
    ///
    /// // Every problem is listed, not only the first.
    /// let err = App::builder()
    ///     .base("blog")
    ///     .route(get("/a", |cx| cx.text(200, "a")))
    ///     .route(get("/a", |cx| cx.text(200, "again")))
    ///     .build()
    ///     .unwrap_err();
    /// assert_eq!(err.problems().len(), 2);
    /// ```
    pub fn build(self) -> std::result::Result<App<G, E>, BuildError> {
        let mut problems = self.early;
        let mut problem = |subject: &str, message: String| {
            problems.push(Problem {
                subject: subject.to_owned(),
                message,
            });
        };

        // Site.
        let base = self.base.trim_end_matches('/');
        if !base.is_empty() {
            match url::normalize(base, self.site.lowercase) {
                Ok(n) if n == base && !base.contains(['?', '#']) => {}
                _ => problem(
                    "base",
                    format!("'{}' is not a canonical path such as '/blog'", self.base),
                ),
            }
        }
        for h in self.site.hosts.iter().chain(&self.site.aliases) {
            if !valid_host(h) {
                problem("host", format!("'{h}' is not a host name or address"));
            }
        }
        if self.site.any_host && !self.site.hosts.is_empty() {
            problem(
                "any_host",
                "any_host() and host(..) contradict each other; keep one".into(),
            );
        }
        if self.site.https_only && self.site.hosts.is_empty() {
            problem(
                "https_only",
                "redirecting to HTTPS needs a declared host; add .host(\"example.com\")".into(),
            );
        }
        if let Some(s) = &self.sign_in {
            if !is_local_target(s) {
                problem("sign_in", format!("'{s}' is not a site-relative path"));
            }
        }
        if self.challenge.is_empty() || !self.challenge.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            problem("www_authenticate", "the value must be visible ASCII".into());
        }

        if !self.security.valid() {
            problem(
                "security_headers",
                "every header value must be visible ASCII and not empty".into(),
            );
        }
        let mut assets = self.assets;
        for a in &mut assets {
            let subject = format!("assets {}", a.mount);
            if a.mount.is_empty()
                || !is_local_target(&a.mount)
                || url::normalize(&a.mount, self.site.lowercase).map_or(true, |n| n != a.mount)
            {
                problem(
                    &subject,
                    "the mount must be a canonical path such as '/static'".into(),
                );
            }
            match std::fs::canonicalize(&a.dir) {
                Ok(root) if root.is_dir() => a.root = root,
                _ => problem(
                    &subject,
                    format!("'{}' is not a folder that exists", a.dir.display()),
                ),
            }
            for r in &self.routes {
                if a.strip(&r.pattern).is_some() {
                    problem(
                        &r.pattern,
                        format!(
                            "the route is under the assets mount '{}' and can never run",
                            a.mount
                        ),
                    );
                }
            }
        }
        for h in &self.redirect_hosts {
            if !valid_host(h) {
                problem(
                    "redirect_hosts",
                    format!("'{h}' is not a host name or address"),
                );
            }
        }
        let mut health = Vec::new();
        for (p, h) in self.health {
            if !is_local_target(&p) || url::normalize(&p, false).map_or(true, |n| n != p) {
                problem(
                    "health",
                    format!("'{p}' is not a canonical site-relative path"),
                );
            }
            health.push((p.into_boxed_str(), h));
        }

        // Routes.
        let mut trie = Trie::default();
        let mut endpoints: Vec<Endpoint> = Vec::new();
        let mut entries: Vec<Entry<G, E>> = Vec::new();
        let mut all = MethodSet::EMPTY;
        for r in self.routes {
            let parts = match router::parse(&r.pattern) {
                Ok(p) => p,
                Err(e) => {
                    problem(&r.pattern, e.message());
                    continue;
                }
            };
            if r.handlers.is_empty() {
                problem(&r.pattern, "the route has no handler".into());
                continue;
            }
            // Request paths are lowered before routing, so a literal with an
            // upper-case letter could never match.
            if self.site.lowercase
                && r.pattern
                    .split('/')
                    .filter(|s| !s.starts_with([':', '*']))
                    .any(|s| s.bytes().any(|b| b.is_ascii_uppercase()))
            {
                problem(
                    &r.pattern,
                    "with lowercase_paths, request paths are lowered, so a literal must be lower case to match".into(),
                );
                continue;
            }
            let mut access = r.access;
            if matches!(access, Access::Undeclared) && rules_impossible::<G::Rule>() {
                // A gate without rules has only public routes.
                access = Access::Public;
            }
            if matches!(access, Access::PublicInRuled) {
                problem(
                    &r.pattern,
                    "the route is public inside a group with a rule; the group's rule holds for every route in it, so move the route out of the group".into(),
                );
                continue;
            }
            if matches!(access, Access::Undeclared) {
                problem(
                    &r.pattern,
                    "the route declares no access; add .public() or .allow(rule)".into(),
                );
                continue;
            }
            let template = match (r.template, &self.render) {
                (None, _) => None,
                (Some(t), None) => {
                    problem(
                        &r.pattern,
                        format!("template '{t}' is declared but no render engine is set"),
                    );
                    None
                }
                (Some(t), Some(engine)) => {
                    let id = engine.template(t);
                    if id.is_none() {
                        problem(&r.pattern, format!("the engine has no template '{t}'"));
                    }
                    id
                }
            };
            let ep = trie.insert(&parts, endpoints.len() as u32) as usize;
            if ep == endpoints.len() {
                endpoints.push(Endpoint {
                    methods: [None; 10],
                    allow: Box::from(""),
                    set: MethodSet::EMPTY,
                });
            }
            let names: Box<[Box<str>]> = router::names(&parts).into();
            if r.csrf_exempt.is_some_and(|reason| reason.trim().is_empty()) {
                problem(&r.pattern, "a CSRF exemption needs its reason".into());
            }
            if let Some(why) = r.cors.as_deref().and_then(Cors::problem) {
                problem(&r.pattern, why.into());
            }
            if let Err(e) = r.form_limits.validate() {
                problem(&r.pattern, format!("the form limits are inconsistent: {e}"));
            }
            for (m, h) in r.handlers {
                let subject = format!("{} {}", m.as_str().unwrap_or("?"), r.pattern);
                if m == Method::Other || m == Method::Connect || m == Method::Trace {
                    problem(&subject, "this method cannot be routed".into());
                    continue;
                }
                let slot = &mut endpoints[ep].methods[m.index() as usize];
                if slot.is_some() {
                    problem(
                        &subject,
                        "a handler for this method and path exists already".into(),
                    );
                    continue;
                }
                *slot = Some(entries.len() as u32);
                let csrf = r.csrf_exempt.is_none() && !m.is_safe();
                if csrf && self.csrf.is_none() {
                    problem(
                        &subject,
                        "an unsafe method needs CSRF protection; set Builder::csrf(..) or mark the route csrf_exempt(\"reason\")".into(),
                    );
                }
                let pick = |at: Hook| -> Box<[HookFn<G::Identity, E>]> {
                    self.hooks
                        .iter()
                        .filter(|(h, sel, _)| *h == at && sel.matches(&r.pattern, r.name))
                        .map(|(_, _, f)| Arc::clone(f))
                        .collect()
                };
                entries.push(Entry {
                    handler: h,
                    access: access.clone(),
                    names: names.clone(),
                    pattern: r.pattern.as_str().into(),
                    work: r.work,
                    template,
                    csrf,
                    limits: r.form_limits,
                    cors: r.cors.clone(),
                    cache: r.cache,
                    cache_values: (
                        r.cache.value(true).map(String::into_boxed_str),
                        r.cache.value(false).map(String::into_boxed_str),
                    ),
                    routed: pick(Hook::Routed),
                    finish: pick(Hook::Finish),
                    before_render: pick(Hook::BeforeRender),
                });
            }
        }
        for e in &mut endpoints {
            let mut set = MethodSet::EMPTY;
            for m in [
                Method::Get,
                Method::Head,
                Method::Post,
                Method::Put,
                Method::Delete,
                Method::Options,
                Method::Patch,
            ] {
                if e.methods[m.index() as usize].is_some() {
                    set = set.with(m);
                }
            }
            if set.contains(Method::Get) {
                set = set.with(Method::Head);
            }
            set = set.with(Method::Options);
            e.set = set;
            all = all.union(set);
            let mut v = Vec::new();
            set.write_allow(&mut v);
            e.allow = String::from_utf8(v).unwrap_or_default().into();
        }
        if !problems.is_empty() {
            return Err(BuildError::new(problems));
        }
        let mut v = Vec::new();
        all.with(Method::Options).write_allow(&mut v);
        Ok(App {
            gate: self.gate,
            shared: Shared {
                render: self.render,
                checkpoint: self.checkpoint,
                events: self.events,
                page_limit: self.page_limit,
                base: base.into(),
                sign_in: self.sign_in.map(Into::into),
                challenge: self.challenge.into(),
                wipe: self.wipe,
                security: self.security,
                csrf: self.csrf,
                redirect_hosts: self.redirect_hosts,
                compression: self.compression,
            },
            site: self.site,
            trie,
            endpoints,
            entries,
            allow_all: String::from_utf8(v).unwrap_or_default().into(),
            assets,
            health,
            streams: assets::Streams::default(),
        })
    }
}

impl<G: Gate> Builder<G, NoRender> {
    /// The template engine. Set it before adding routes and hooks: their
    /// handlers are typed by it, so any added before are dropped and the
    /// build says so.
    ///
    /// ```
    /// use web_net::{App, Context, Guest, Output, Render, RenderError, TemplateId, get};
    ///
    /// struct Pages;
    /// impl Render for Pages {
    ///     type View<'a> = str;
    ///     fn template(&self, name: &str) -> Option<TemplateId> {
    ///         (name == "page").then_some(TemplateId(0))
    ///     }
    ///     fn render(&self, _: TemplateId, title: &str, out: &mut Output<'_>) -> Result<(), RenderError> {
    ///         out.write_str("<h1>")?;
    ///         out.write_str(title)?; // a real engine escapes
    ///         out.write_str("</h1>")
    ///     }
    /// }
    ///
    /// let app = App::builder()
    ///     .render(Pages)
    ///     .route(get("/", |cx: &mut Context<'_, Guest, Pages>| cx.render("Home")).template("page"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "<h1>Home</h1>");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn render<E: Render>(self, engine: E) -> Builder<G, E> {
        let mut b = Builder::new(self.gate);
        if !self.routes.is_empty() || !self.hooks.is_empty() {
            b.early.push(Problem {
                subject: "render".into(),
                message: "set the template engine before adding routes and hooks".into(),
            });
        }
        b.render = Some(engine);
        b.site = self.site;
        b.base = self.base;
        b.checkpoint = self.checkpoint;
        b.events = self.events;
        b.page_limit = self.page_limit;
        b.sign_in = self.sign_in;
        b.challenge = self.challenge;
        b.wipe = self.wipe;
        b.security = self.security;
        b.assets = self.assets;
        b.health = self.health;
        b.csrf = self.csrf;
        b.redirect_hosts = self.redirect_hosts;
        b.compression = self.compression;
        b
    }
}

impl<G: Gate, E: Render> fmt::Debug for Builder<G, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Builder")
            .field("routes", &self.routes)
            .field("site", &self.site)
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

/// Whether the gate's rule type is [`NoRule`](crate::NoRule), which has no
/// values: no route can be anything but public.
fn rules_impossible<R: 'static>() -> bool {
    std::any::TypeId::of::<R>() == std::any::TypeId::of::<crate::NoRule>()
}

fn valid_host(h: &str) -> bool {
    let (host, port) = split_port(h);
    let host_ok = if let Some(inner) = host.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        inner.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    };
    host_ok && port.is_none_or(|p| !p.is_empty() && p.parse::<u16>().is_ok())
}

/// `example.com:8080` to (`example.com`, `Some("8080")`); `[::1]:80` to
/// (`[::1]`, `Some("80")`).
fn split_port(a: &str) -> (&str, Option<&str>) {
    if a.starts_with('[') {
        return match a.find(']') {
            Some(i) => match a[i + 1..].strip_prefix(':') {
                Some(p) => (&a[..=i], Some(p)),
                None => (a, None),
            },
            None => (a, None),
        };
    }
    match a.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (a, None),
    }
}

/// Case-insensitive, so no request needs a lower-case copy of its host.
fn is_dev_host(host: &str) -> bool {
    const SUFFIX: &[u8] = b".localhost";
    let b = host.as_bytes();
    ["localhost", "127.0.0.1", "[::1]"]
        .iter()
        .any(|d| d.eq_ignore_ascii_case(host))
        || (b.len() > SUFFIX.len() && b[b.len() - SUFFIX.len()..].eq_ignore_ascii_case(SUFFIX))
}

/// The authority without trailing dots, and its host without the port.
fn host_parts(authority: &str) -> (&str, &str) {
    let full = authority.trim_end_matches('.');
    (full, split_port(full).0.trim_end_matches('.'))
}

/// Whether a declared host (lower case) names this authority: the whole
/// authority, or the host when the declared one has no port.
fn host_listed(list: &[Box<str>], full: &str, host: &str) -> bool {
    list.iter().any(|h| {
        h.eq_ignore_ascii_case(full) || (split_port(h).1.is_none() && h.eq_ignore_ascii_case(host))
    })
}

thread_local! {
    /// Reply buffers reused between requests on one thread. Taken for the
    /// length of one request and put back, so nothing about a request lives
    /// here between calls.
    static SCRATCH: Cell<Option<Box<Out>>> = const { Cell::new(None) };
}

/// Buffers bigger than this are dropped instead of kept.
const KEEP_CAPACITY: usize = 1 << 20;

/// Where the site check sent a request.
enum Placed<'a> {
    Here(Cow<'a, str>),
    Redirect(String),
    Refuse(u16, &'static str, Option<url::UrlError>),
}

impl<G: Gate, E: Render> App<G, E> {
    /// Serves the application on `addr` (`"127.0.0.1:8080"`): one TCP
    /// listener per address it resolves to, with serve-net's default
    /// limits, keep-alive, and workers. For TLS, several listeners, or
    /// other limits, hand the app to `serve_net::Server::builder()...serve(app)`.
    ///
    /// ```no_run
    /// use web_net::{App, get};
    ///
    /// App::builder()
    ///     .route(get("/", |cx| cx.html(200, "<h1>Hello</h1>")))
    ///     .build()?
    ///     .listen("127.0.0.1:8080")?
    ///     .wait();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// serve-net's [`ServeError`](serve_net::ServeError): the address does
    /// not resolve, or a port cannot be bound.
    pub fn listen(
        self,
        addr: impl std::net::ToSocketAddrs,
    ) -> std::result::Result<serve_net::Running, serve_net::ServeError> {
        listen(addr, self)
    }

    /// Runs the pipeline for one request, for a wrapper that holds the app
    /// (a gateway). `who` is `Some` when the wrapper authenticated the
    /// request already: web-net takes it as given and does not call the
    /// gate's `authenticate` (nor write the gate's cookie). Authorization
    /// still runs for every route that is not public. `None` runs the whole
    /// pipeline, as serve-net's `HttpService::call` does.
    ///
    /// The report says what ran and whether a cache in front may keep the
    /// reply for guests.
    ///
    /// A wrapper forwards serve-net's `HttpService::done` to the app as
    /// well (`HttpService::done(&app, env, finished)`): a large file sent in
    /// parts keeps a record until its last part or until `done`, and records
    /// of downloads the client dropped are freed only there. Without it they
    /// accumulate until new large-file replies are refused with 503.
    ///
    /// ```
    /// use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};
    /// use web_net::{App, Guest, get};
    ///
    /// // A front that authenticated every request already.
    /// struct Front(App);
    /// impl HttpService for Front {
    ///     fn call(&self, req: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
    ///         self.0.respond(req, env, Some(&Guest), reply).outcome
    ///     }
    /// }
    ///
    /// let front = Front(App::builder().route(get("/", |cx| cx.text(200, "hi"))).build()?);
    /// let r = serve_net::testing::respond(&front, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "hi");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    pub fn respond(
        &self,
        req: &HttpRequest<'_>,
        env: &Envelope,
        who: Option<&G::Identity>,
        reply: &mut HttpReply,
    ) -> Served {
        let mut report = Served {
            outcome: Outcome::Done,
            route: None,
            cache: Cacheable::No,
        };
        // Handlers and hooks are caught where they run; this catches the
        // rest of the application's code on the request path (the gate, a
        // checkpoint, a readiness check, identity methods). Whatever the
        // reply held is discarded and the built-in 500 goes out instead.
        match catch_unwind(AssertUnwindSafe(|| {
            self.run(req, env, who, reply, &mut report)
        })) {
            Ok(outcome) => report.outcome = outcome,
            Err(_) => {
                *reply.parts_mut() = Default::default();
                report = Served {
                    outcome: Outcome::Done,
                    route: None,
                    cache: Cacheable::No,
                };
                let at = At {
                    env,
                    tls: self.tls(env, req.head().authority()),
                    json: wants_json(req.header("accept")),
                };
                self.refuse_with(
                    500,
                    "pipeline.panic",
                    EventKind::Panicked,
                    None,
                    None,
                    at,
                    reply,
                    false,
                );
            }
        }
        report
    }

    /// Looks at a head before admission: which route would run and how it
    /// behaves. Nothing is answered and no gate is called.
    ///
    /// ```
    /// use serve_net::WorkClass;
    /// use web_net::{App, get};
    /// use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};
    ///
    /// // A dispatcher in front of the app that answers with what `classify` said.
    /// struct Probe(App);
    /// impl HttpService for Probe {
    ///     fn call(&self, req: &HttpRequest<'_>, _: &Envelope, reply: &mut HttpReply) -> Outcome {
    ///         let c = self.0.classify(req.head());
    ///         reply.text(200, &format!("{:?} {:?}", c.route, c.work));
    ///         Outcome::Done
    ///     }
    /// }
    ///
    /// let app = App::builder()
    ///     .route(get("/report", |cx| cx.text(200, "report")).work(WorkClass::Io))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&Probe(app), b"GET /report HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "Some(RouteId(0)) Io");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn classify(&self, head: &HttpHead<'_>) -> Classified {
        let none = Classified {
            route: None,
            work: WorkClass::Quick,
        };
        let Placed::Here(path) = self.place(head.authority(), head.path(), Scheme::Https, true)
        else {
            return none;
        };
        let Some((ep, _)) = self.trie.find(&path) else {
            return none;
        };
        match self.entry_for(ep as usize, head.method()) {
            Some(i) => Classified {
                route: Some(RouteId(i)),
                work: self.entries[i as usize].work,
            },
            None => none,
        }
    }

    /// `Ok` when `who` may use at least one method of the endpoint (one is
    /// public, or every rule of one allows); else the first denial.
    fn may_use_any<'r>(
        &'r self,
        endpoint: &Endpoint,
        who: &G::Identity,
        req: &mut Request<'r>,
    ) -> std::result::Result<(), Denial> {
        let mut first = None;
        for i in endpoint.methods.iter().flatten() {
            let entry = &self.entries[*i as usize];
            let rules = match &entry.access {
                Access::Rules(rules) => rules,
                _ => return Ok(()),
            };
            req.route = Some(&entry.pattern);
            match rules
                .iter()
                .try_for_each(|r| self.gate.authorize(who, r, req))
            {
                Ok(()) => return Ok(()),
                Err(d) => {
                    first.get_or_insert(d);
                }
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// What a request held once it is over, for `HttpService::done`.
    pub(crate) fn forget(&self, env: &Envelope) {
        self.streams
            .remove((env.connection().get(), env.seq().get()));
    }

    /// The gate.
    ///
    /// ```
    /// use web_net::{App, Open};
    ///
    /// let app = App::builder().build()?;
    /// let gate: &Open = app.gate();
    /// # let _ = gate;
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn gate(&self) -> &G {
        &self.gate
    }

    fn entry_for(&self, ep: usize, m: Method) -> Option<u32> {
        let methods = &self.endpoints[ep].methods;
        match m {
            Method::Other => None,
            Method::Head => {
                methods[Method::Head.index() as usize].or(methods[Method::Get.index() as usize])
            }
            m => methods[m.index() as usize],
        }
    }

    /// Steps 1 and 2: which site, which canonical path. `quiet` (for
    /// `classify`) skips building a redirect.
    fn place<'a>(
        &self,
        authority: Option<&'a str>,
        raw: &'a str,
        scheme: Scheme,
        quiet: bool,
    ) -> Placed<'a> {
        let site = &self.site;
        let authority = authority.unwrap_or("");
        let (full, host_only) = host_parts(authority);
        let listed = |list: &[Box<str>]| host_listed(list, full, host_only);
        // With no host declared, the development hosts are the site, and no
        // other: a name rebound to this address by someone else's DNS is
        // not (DNS rebinding), unless the site said `any_host`.
        let dev_only = site.hosts.is_empty() && !site.any_host;
        let dev = (site.development || dev_only) && is_dev_host(host_only);
        if dev_only && !dev {
            return Placed::Refuse(421, "host.unknown", None);
        }
        let mut target_host: Option<&str> = None;
        // With hosts declared, an empty or missing Host is as unknown as any
        // other host.
        if !site.hosts.is_empty() && !dev && !listed(&site.hosts) {
            if listed(&site.aliases) {
                target_host = site.hosts.first().map(AsRef::as_ref);
            } else {
                return Placed::Refuse(421, "host.unknown", None);
            }
        }
        let mut https = scheme == Scheme::Https;
        if site.https_only && !https && !dev {
            https = true;
            target_host = target_host.or(site.hosts.first().map(AsRef::as_ref));
        }

        // The path: canonical, inside the base, with the slash policy.
        let canon = match url::normalize(raw, site.lowercase) {
            Ok(c) => c,
            Err(e) => return Placed::Refuse(400, e.code(), Some(e)),
        };
        let base = self.shared.base.as_ref();
        let c: &str = &canon;
        let rel_start = if base.is_empty() {
            0
        } else if c == base {
            c.len()
        } else if c.strip_prefix(base).is_some_and(|r| r.starts_with('/')) {
            base.len()
        } else {
            return Placed::Refuse(404, "site.outside_base", None);
        };
        let rel = &c[rel_start..];
        let mut fixed: Option<String> = None;
        let health = self.health.iter().any(|(p, _)| p.as_ref() == rel);
        if rel.is_empty() {
            fixed = Some("/".into());
        } else if rel.len() > 1 && !health {
            match site.slash {
                TrailingSlash::Strip => {
                    if let Some(s) = rel.strip_suffix('/') {
                        fixed = Some(s.to_owned());
                    }
                }
                TrailingSlash::Add => {
                    let trimmed = rel.strip_suffix('/').unwrap_or(rel);
                    let file_like = trimmed.rsplit('/').next().unwrap_or("").contains('.');
                    if file_like && rel.ends_with('/') {
                        // `/style.css/` and `/style.css` are one page: no slash.
                        fixed = Some(trimmed.to_owned());
                    } else if !file_like && !rel.ends_with('/') {
                        fixed = Some(format!("{rel}/"));
                    }
                }
                TrailingSlash::Ignore => {}
            }
        }
        if target_host.is_none() && fixed.is_none() {
            if let Cow::Borrowed(c) = canon {
                let mut path = &c[rel_start..];
                if site.slash == TrailingSlash::Ignore && path.len() > 1 {
                    path = path.strip_suffix('/').unwrap_or(path);
                }
                return Placed::Here(Cow::Borrowed(path));
            }
        }
        if quiet {
            return Placed::Refuse(0, "", None);
        }
        let rel_out = fixed.as_deref().unwrap_or(rel);
        let mut loc = String::with_capacity(raw.len() + 32);
        if let Some(h) = target_host {
            loc.push_str(if https { "https://" } else { "http://" });
            loc.push_str(h);
        }
        loc.push_str(base);
        loc.push_str(rel_out);
        Placed::Redirect(loc)
    }

    fn run(
        &self,
        http: &HttpRequest<'_>,
        env: &Envelope,
        who: Option<&G::Identity>,
        reply: &mut HttpReply,
        report: &mut Served,
    ) -> Outcome {
        let method = http.method();
        let raw_path = http.path();
        let authority = http.head().authority();
        let at = At {
            env,
            tls: self.tls(env, authority),
            json: wants_json(http.header("accept")),
        };
        if raw_path == "*" {
            // The host is checked as for any request: `OPTIONS *` to a host
            // the site does not serve is a 421 too.
            if self.claim(authority, &self.shared.base).is_none() {
                self.refuse(
                    421,
                    "host.unknown",
                    EventKind::Refused,
                    None,
                    None,
                    at,
                    reply,
                );
                return Outcome::Done;
            }
            if method == Method::Options {
                reply.status(204).header("allow", self.allow_all.as_bytes());
                self.secure(reply, at.tls, |_| false);
            } else {
                self.refuse(
                    400,
                    "url.asterisk",
                    EventKind::Refused,
                    None,
                    None,
                    at,
                    reply,
                );
            }
            return Outcome::Done;
        }
        let host_raw = authority.unwrap_or("");
        let placed = self.place(authority, raw_path, env.client().scheme(), false);
        let path = match placed {
            Placed::Here(path) => path,
            Placed::Redirect(mut loc) => {
                if let Some(q) = http.query() {
                    loc.push('?');
                    loc.push_str(q);
                }
                let status = if matches!(method, Method::Get | Method::Head) {
                    301
                } else {
                    308
                };
                reply.status(status).header("location", loc.as_bytes());
                self.secure(reply, at.tls, |_| false);
                return Outcome::Done;
            }
            Placed::Refuse(status, code, src) => {
                let src = src
                    .as_ref()
                    .map(|e| e as &(dyn std::error::Error + 'static));
                self.refuse(status, code, EventKind::Refused, None, src, at, reply);
                return Outcome::Done;
            }
        };
        // Early: health paths and files, before the gate and the router.
        if let Some(outcome) = self.early(http, at, &path, reply) {
            return outcome;
        }
        // CORS preflights carry no credentials: answered before the gate.
        if let Some(outcome) = self.preflight(http, at, &path, reply) {
            return outcome;
        }

        let req = Request {
            http,
            env,
            path: &path,
            host: host_raw,
            route: None,
            tls: at.tls,
            json: at.json,
        };

        // Authentication, unless the caller did it.
        let owned;
        let owned_here = who.is_none();
        let who: &G::Identity = match who {
            Some(w) => w,
            None => match self.gate.authenticate(&req) {
                Ok(w) => {
                    owned = w;
                    &owned
                }
                Err(d) => {
                    self.deny(d, &req, reply);
                    return Outcome::Done;
                }
            },
        };

        let mut gate_cookie = if owned_here { who.set_cookie() } else { None };
        let outcome = self.routed(http, env, at, req, who, &mut gate_cookie, reply, report);
        // The gate's own cookie (a dead session cleared, a pre-session id
        // set) leaves on every exit after authentication, once. A handler's
        // reply wrote it already, before the handler's own fields (so a
        // fresh session cookie set by the handler wins); every other exit
        // writes it here. A caller that authenticated itself writes its own.
        if let Some(c) = gate_cookie {
            reply.header("set-cookie", c.as_bytes());
            report.cache = Cacheable::No;
        }
        outcome
    }

    /// Steps 4 onward: route, method, authorization, CSRF, the handler.
    #[allow(clippy::too_many_arguments)]
    fn routed<'r>(
        &'r self,
        http: &HttpRequest<'_>,
        env: &Envelope,
        at: At<'_>,
        mut req: Request<'r>,
        who: &G::Identity,
        gate_cookie: &mut Option<&str>,
        reply: &mut HttpReply,
        report: &mut Served,
    ) -> Outcome {
        let method = http.method();
        let path = req.path;
        let host_raw = req.host;
        // Route and method.
        let Some((ep, caps)) = self.trie.find(path) else {
            self.refuse(404, "route.none", EventKind::Refused, None, None, at, reply);
            return Outcome::Done;
        };
        let endpoint = &self.endpoints[ep as usize];
        let Some(idx) = self.entry_for(ep as usize, method) else {
            // The method answers (405, `OPTIONS`) say the path exists, so
            // they go only to someone who may use one of its methods: a
            // route the gate hides reads as missing for every method.
            if let Err(d) = self.may_use_any(endpoint, who, &mut req) {
                self.deny(d, &req, reply);
                return Outcome::Done;
            }
            if method == Method::Options {
                reply.status(204).header("allow", endpoint.allow.as_bytes());
                self.secure(reply, at.tls, |_| false);
                return Outcome::Done;
            }
            let status = if method == Method::Other { 501 } else { 405 };
            let code = if status == 501 {
                "method.unknown"
            } else {
                "method.not_allowed"
            };
            self.refuse(status, code, EventKind::Refused, None, None, at, reply);
            if status == 405 {
                reply.header("allow", endpoint.allow.as_bytes());
            }
            return Outcome::Done;
        };
        let entry = &self.entries[idx as usize];
        req.route = Some(&entry.pattern);
        report.route = Some(RouteId(idx));

        // Authorization: every rule, the groups' first.
        if let Access::Rules(rules) = &entry.access {
            for rule in rules {
                if let Err(d) = self.gate.authorize(who, rule, &req) {
                    self.deny(d, &req, reply);
                    return Outcome::Done;
                }
            }
        }
        if let Some(cp) = &self.shared.checkpoint {
            match cp.check(env, Stage::Authorized) {
                Verdict::Pass => {}
                Verdict::Deny { status } => {
                    // A refusal is an error status, whatever the checkpoint
                    // said: anything else is answered as 403.
                    let status = if (400..=599).contains(&status) {
                        status
                    } else {
                        403
                    };
                    self.refuse(
                        status,
                        "checkpoint.denied",
                        EventKind::Revoked,
                        req.route,
                        None,
                        at,
                        reply,
                    );
                    return Outcome::Done;
                }
                _ => {
                    self.refuse(
                        403,
                        "checkpoint.killed",
                        EventKind::Revoked,
                        req.route,
                        None,
                        at,
                        reply,
                    );
                    return Outcome::Close;
                }
            }
        }

        // CSRF on unsafe methods.
        let binding = who.csrf_binding();
        match (&self.shared.csrf, entry.csrf) {
            (Some(engine), true) => {
                let scheme = if env.client().scheme() == Scheme::Https {
                    "https://"
                } else {
                    "http://"
                };
                let own = format!("{scheme}{}", host_raw.to_ascii_lowercase());
                match csrf::check(engine, http, binding, &own, &entry.limits) {
                    Ok(()) => {}
                    Err(code) => {
                        self.refuse(403, code, EventKind::Denied, req.route, None, at, reply);
                        return Outcome::Done;
                    }
                }
            }
            // Built only with an engine when a route needs one.
            (None, true) => {
                self.refuse(
                    500,
                    "csrf.no_engine",
                    EventKind::Failed,
                    req.route,
                    None,
                    at,
                    reply,
                );
                return Outcome::Done;
            }
            (_, false) => {}
        }

        // The handler, with its hooks, on a buffer web-net holds.
        let mut out = SCRATCH.with(Cell::take).unwrap_or_default();
        out.reset();
        let outcome = self.handle(
            entry,
            req,
            who,
            caps,
            (gate_cookie, binding),
            &mut out,
            reply,
            &mut report.cache,
        );
        if self.shared.wipe {
            out.wipe();
        }
        if out.body.capacity() <= KEEP_CAPACITY && out.values.capacity() <= KEEP_CAPACITY {
            SCRATCH.with(|s| s.set(Some(out)));
        }
        outcome
    }

    /// A CORS preflight for a route with a policy: answered before the gate.
    fn preflight(
        &self,
        http: &HttpRequest<'_>,
        at: At<'_>,
        path: &str,
        reply: &mut HttpReply,
    ) -> Option<Outcome> {
        if http.method() != Method::Options {
            return None;
        }
        let origin = http.header("origin")?;
        let wanted = Method::from_bytes(http.header("access-control-request-method")?);
        let (ep, _) = self.trie.find(path)?;
        let ep = ep as usize;
        if self.entry_for(ep, Method::Options).is_some() {
            return None;
        }
        let cors = self
            .entry_for(ep, wanted)
            .and_then(|i| self.entries[i as usize].cors.as_ref())?;
        // Only the methods whose routes share this policy.
        let mut set = MethodSet::EMPTY;
        for m in self.endpoints[ep].set.iter() {
            let shares = self.entry_for(ep, m).is_some_and(|i| {
                self.entries[i as usize]
                    .cors
                    .as_ref()
                    .is_some_and(|c| Arc::ptr_eq(c, cors))
            });
            if shares {
                set = set.with(m);
            }
        }
        let ok = cors.preflight(
            origin,
            wanted,
            http.header("access-control-request-headers"),
            set,
            reply,
        );
        if !ok {
            self.event(EventKind::Refused, at.env, None, 204, "cors.denied", None);
        }
        self.secure(reply, at.tls, |_| false);
        Some(Outcome::Done)
    }

    /// Health paths and static files.
    fn early(
        &self,
        http: &HttpRequest<'_>,
        at: At<'_>,
        path: &str,
        reply: &mut HttpReply,
    ) -> Option<Outcome> {
        let method = http.method();
        let get_like = matches!(method, Method::Get | Method::Head);
        if let Some((_, h)) = self.health.iter().find(|(p, _)| p.as_ref() == path) {
            if !get_like {
                self.not_get(method, at, reply);
                return Some(Outcome::Done);
            }
            let (status, text) = match h {
                Health::Live => (200, "ok"),
                Health::Ready(f) if f() => (200, "ready"),
                Health::Ready(_) => (503, "not ready"),
            };
            reply.text(status, text).header("cache-control", "no-store");
            self.secure(reply, at.tls, |_| false);
            return Some(Outcome::Done);
        }
        let (assets, rel) = self
            .assets
            .iter()
            .find_map(|a| a.strip(path).map(|rel| (a, rel)))?;
        if !get_like {
            self.not_get(method, at, reply);
            return Some(Outcome::Done);
        }
        let key = (at.env.connection().get(), at.env.seq().get());
        if let Some(stream) = self.streams.take(key) {
            // A later part of a large file: the file found for the first
            // part, unchanged, or the end of the connection; never another
            // reply inside this one.
            return Some(assets::next_part(&self.streams, key, stream, reply));
        }
        let found = assets::find(assets, rel, http.header("accept-encoding"));
        let Some(found) = found else {
            self.refuse(
                404,
                "assets.none",
                EventKind::Refused,
                None,
                None,
                at,
                reply,
            );
            return Some(Outcome::Done);
        };
        match assets::serve(assets, &found, &self.streams, key, http, reply) {
            Ok(outcome) => {
                self.secure(reply, at.tls, |_| false);
                Some(outcome)
            }
            Err(assets::Unserved::Busy) => {
                // Every slot holds a download in progress: refused cleanly,
                // never by forgetting one of them.
                self.refuse(
                    503,
                    "assets.busy",
                    EventKind::Refused,
                    None,
                    None,
                    at,
                    reply,
                );
                reply.header("retry-after", "5");
                Some(Outcome::Done)
            }
            Err(assets::Unserved::Unreadable) => {
                self.refuse(
                    500,
                    "assets.unreadable",
                    EventKind::Failed,
                    None,
                    None,
                    at,
                    reply,
                );
                Some(Outcome::Done)
            }
        }
    }

    /// 405 (or 204 for `OPTIONS`) on a path that takes `GET` and `HEAD` only.
    fn not_get(&self, method: Method, at: At<'_>, reply: &mut HttpReply) {
        if method == Method::Options {
            reply.status(204).header("allow", "GET, HEAD, OPTIONS");
            self.secure(reply, at.tls, |_| false);
        } else {
            let (status, code) = if method == Method::Other {
                (501, "method.unknown")
            } else {
                (405, "method.not_allowed")
            };
            self.refuse(status, code, EventKind::Refused, None, None, at, reply);
            if status == 405 {
                reply.header("allow", "GET, HEAD, OPTIONS");
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle(
        &self,
        entry: &Entry<G, E>,
        req: Request<'_>,
        who: &G::Identity,
        caps: Captures,
        (gate_cookie, binding): (&mut Option<&str>, Option<&[u8]>),
        out: &mut Out,
        reply: &mut HttpReply,
        cacheable: &mut Cacheable,
    ) -> Outcome {
        let at = At {
            env: req.env,
            tls: req.tls,
            json: req.json,
        };
        let route = req.route;
        let http = req.http;
        let guest = who.is_guest();
        let result = {
            let mut cx = Context {
                req,
                who,
                caps,
                names: &entry.names,
                out: &mut *out,
                shared: &self.shared,
                template: entry.template,
                binding,
                limits: &entry.limits,
                before_render: &entry.before_render,
                rendering: false,
            };
            catch_unwind(AssertUnwindSafe(|| -> Result {
                for h in entry.routed.iter() {
                    h(&mut cx)?;
                }
                entry.handler.call(&mut cx)?;
                for h in entry.finish.iter() {
                    h(&mut cx)?;
                }
                Ok(())
            }))
        };
        match result {
            Ok(Ok(())) if !out.invalid => {
                // A handler that sets the gate's cookie itself (a new session
                // after sign-in) replaces it: the gate's is not sent.
                if gate_cookie.is_some_and(|c| out.sets_cookie(c)) {
                    *gate_cookie = None;
                }
                // A reply that sets a cookie is never public, whatever the
                // policy or the handler said: a shared cache would give one
                // visitor's cookie (a pre-session id, the CSRF binding) to
                // every guest.
                let cookies = gate_cookie.is_some() || out.has("set-cookie");
                let ours = !out.has("cache-control");
                if cookies {
                    let public = out
                        .get("cache-control")
                        .is_some_and(|v| v.windows(6).any(|w| w.eq_ignore_ascii_case(b"public")));
                    if ours || public {
                        out.remove("cache-control");
                        out.header("cache-control", b"private, no-store");
                    }
                } else if ours {
                    let (for_guest, for_member) = &entry.cache_values;
                    let value = if guest { for_guest } else { for_member };
                    if let Some(v) = value {
                        out.header("cache-control", v.as_bytes());
                    }
                }
                if let Some(c) = self.shared.compression {
                    compress(c, http.header("accept-encoding"), out);
                }
                *cacheable = match entry.cache {
                    CachePolicy::Guests { max_age } | CachePolicy::Public { max_age }
                        if guest
                            && ours
                            && !cookies
                            && entry.cors.is_none()
                            && matches!(http.method(), Method::Get | Method::Head)
                            && out.status == 200
                            && out
                                .get("vary")
                                .is_none_or(|v| v.eq_ignore_ascii_case(b"accept-encoding")) =>
                    {
                        Cacheable::Guests { max_age }
                    }
                    _ => Cacheable::No,
                };
                reply.status(out.status);
                if let Some(c) = gate_cookie.take() {
                    reply.header("set-cookie", c.as_bytes());
                }
                for &(ns, ne, vs, ve) in &out.spans {
                    let name = core::str::from_utf8(&out.names[ns as usize..ne as usize])
                        .unwrap_or("x-invalid");
                    reply.header(name, &out.values[vs as usize..ve as usize]);
                }
                if !out.has("x-content-type-options") {
                    reply.header("x-content-type-options", "nosniff");
                }
                if let Some(cors) = &entry.cors {
                    cors.actual(http.header("origin"), reply);
                }
                self.secure(reply, at.tls, |n| out.has(n));
                reply.body(&out.body);
                Outcome::Done
            }
            Ok(Ok(())) => {
                out.reset();
                self.refuse(
                    500,
                    "reply.invalid_field",
                    EventKind::Failed,
                    route,
                    None,
                    at,
                    reply,
                );
                Outcome::Done
            }
            Ok(Err(e)) => {
                out.reset();
                let src = std::error::Error::source(&e);
                self.refuse(
                    e.status(),
                    e.code(),
                    EventKind::Failed,
                    route,
                    src,
                    at,
                    reply,
                );
                Outcome::Done
            }
            Err(_) => {
                out.reset();
                self.refuse(
                    500,
                    "handler.panic",
                    EventKind::Panicked,
                    route,
                    None,
                    at,
                    reply,
                );
                Outcome::Done
            }
        }
    }

    /// A gate's denial as a response.
    fn deny(&self, d: Denial, req: &Request<'_>, reply: &mut HttpReply) {
        let env = req.env;
        let at = At {
            env,
            tls: req.tls,
            json: req.json,
        };
        if d.kind() == DenialKind::SignIn {
            if let Some(page) = &self.shared.sign_in {
                if matches!(req.method(), Method::Get | Method::Head) {
                    let mut loc = String::with_capacity(64);
                    loc.push_str(&self.shared.base);
                    loc.push_str(page);
                    loc.push_str(if page.contains('?') {
                        "&next="
                    } else {
                        "?next="
                    });
                    let mut next = String::new();
                    next.push_str(&self.shared.base);
                    next.push_str(req.path);
                    if let Some(q) = req.query() {
                        next.push('?');
                        next.push_str(q);
                    }
                    encode_component(&next, &mut loc);
                    self.event(EventKind::Denied, env, req.route, 303, d.code(), None);
                    reply.status(303).header("location", loc.as_bytes());
                    self.secure(reply, at.tls, |_| false);
                    if let Some(c) = d.cookie() {
                        reply.header("set-cookie", c.as_bytes());
                    }
                    return;
                }
            }
        }
        let status = d.status();
        self.refuse(
            status,
            d.code(),
            EventKind::Denied,
            req.route,
            None,
            at,
            reply,
        );
        if status == 401 {
            reply.header("www-authenticate", self.shared.challenge.as_bytes());
        }
        if let Some(seconds) = d.retry_seconds().filter(|_| matches!(status, 429 | 503)) {
            reply.header("retry-after", seconds.to_string().as_bytes());
        }
        if let Some(c) = d.cookie() {
            reply.header("set-cookie", c.as_bytes());
        }
    }

    fn event(
        &self,
        kind: EventKind,
        env: &Envelope,
        route: Option<&str>,
        status: u16,
        code: &'static str,
        source: Option<&(dyn std::error::Error + 'static)>,
    ) {
        let event = Event {
            kind,
            id: RequestId::of(env),
            route,
            status,
            code,
            source,
        };
        // A sink that panics loses its event, never the visitor's reply.
        let _ = catch_unwind(AssertUnwindSafe(|| self.shared.events.event(&event)));
    }

    /// The one function every refusal and error goes through: the status,
    /// the error template for it or the built-in page, the reference; the
    /// code and source to the events only.
    #[allow(clippy::too_many_arguments)]
    fn refuse(
        &self,
        status: u16,
        code: &'static str,
        kind: EventKind,
        route: Option<&str>,
        source: Option<&(dyn std::error::Error + 'static)>,
        at: At<'_>,
        reply: &mut HttpReply,
    ) {
        self.refuse_with(status, code, kind, route, source, at, reply, true);
    }

    /// [`refuse`](Self::refuse); `engine` false gives the built-in page
    /// without asking the engine (after a panic, the engine may be what
    /// failed).
    #[allow(clippy::too_many_arguments)]
    fn refuse_with(
        &self,
        status: u16,
        code: &'static str,
        kind: EventKind,
        route: Option<&str>,
        source: Option<&(dyn std::error::Error + 'static)>,
        at: At<'_>,
        reply: &mut HttpReply,
        engine: bool,
    ) {
        self.event(kind, at.env, route, status, code, source);
        let reference = RequestId::of(at.env).to_string();
        let mut body = Vec::with_capacity(512);
        if at.json {
            error::json_body(status, &reference, &mut body);
            reply
                .status(status)
                .header("content-type", "application/json")
                .header("x-content-type-options", "nosniff")
                .header("cache-control", "no-store")
                .body(&body);
            self.secure(reply, at.tls, |_| false);
            return;
        }
        let mut done = false;
        if let Some(engine) = self.shared.render.as_ref().filter(|_| engine) {
            let page = ErrorPage {
                status,
                title: error::title(status),
                message: error::message(status),
                reference: &reference,
                base: &self.shared.base,
            };
            let wrote = catch_unwind(AssertUnwindSafe(|| {
                let mut out = Output::new(&mut body, self.shared.page_limit);
                let wrote = engine.error_page(&page, &mut out);
                matches!(wrote, Ok(true)) && !out.over()
            }));
            match wrote {
                Ok(true) => done = true,
                Ok(false) => body.clear(),
                Err(_) => {
                    body.clear();
                    self.event(
                        EventKind::Panicked,
                        at.env,
                        route,
                        status,
                        "render.error_page_panic",
                        None,
                    );
                }
            }
        }
        if !done {
            error::builtin_page(status, &reference, &mut body);
        }
        reply
            .status(status)
            .header("content-type", "text/html; charset=utf-8")
            .header("x-content-type-options", "nosniff")
            .header("cache-control", "no-store")
            .body(&body);
        self.secure(reply, at.tls, |_| false);
    }

    /// Adds the policy's security headers, except those `has` says the reply
    /// set already.
    fn secure(&self, reply: &mut HttpReply, tls: bool, has: impl Fn(&str) -> bool) {
        for (name, value) in self.shared.security.fields(tls) {
            if !has(name) {
                reply.header(name, value.as_bytes());
            }
        }
    }

    /// How well this application claims a request, for [`Sites`](crate::Sites):
    /// the host's rank (2 listed or an alias, 1 a development host, 0 any
    /// host accepted) and the base path's length. `None`: not this site.
    pub(crate) fn claim(&self, authority: Option<&str>, path: &str) -> Option<(u8, usize)> {
        let (full, host_only) = host_parts(authority.unwrap_or(""));
        let listed = |list: &[Box<str>]| host_listed(list, full, host_only);
        let rank = if self.site.hosts.is_empty() && self.site.any_host {
            0
        } else if self.site.hosts.is_empty() {
            if is_dev_host(host_only) {
                1
            } else {
                return None;
            }
        } else if listed(&self.site.hosts) || listed(&self.site.aliases) {
            2
        } else if self.site.development && is_dev_host(host_only) {
            1
        } else {
            return None;
        };
        let base = self.shared.base.as_ref();
        // A site with lower-case paths claims `/BLOG/x` too: it redirects it
        // to `/blog/x` itself, instead of another site answering it.
        let head = path.get(..base.len());
        let starts = head.is_some_and(|h| {
            if self.site.lowercase {
                h.eq_ignore_ascii_case(base)
            } else {
                h == base
            }
        });
        let inside = base.is_empty()
            || (starts && matches!(path.as_bytes().get(base.len()), None | Some(b'/')));
        inside.then_some((rank, base.len()))
    }

    /// Whether HTTPS-only headers apply: the request came over HTTPS and is
    /// not for a development host.
    fn tls(&self, env: &Envelope, authority: Option<&str>) -> bool {
        if env.client().scheme() != Scheme::Https {
            return false;
        }
        let (_, host) = host_parts(authority.unwrap_or(""));
        !(self.site.development && is_dev_host(host))
    }
}

impl<G: Gate, E: Render> HttpService for App<G, E> {
    fn call(&self, request: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        self.respond(request, env, None, reply).outcome
    }

    /// Frees what the request held: the record of a large file going out
    /// in parts, when the client left before its end.
    fn done(&self, env: &Envelope, _finished: &serve_net::Finished) {
        self.forget(env);
    }
}

/// One TCP listener per address `addr` resolves to, serving `service`.
pub(crate) fn listen<S: HttpService + 'static>(
    addr: impl std::net::ToSocketAddrs,
    service: S,
) -> std::result::Result<serve_net::Running, serve_net::ServeError> {
    let addrs: Vec<std::net::SocketAddr> = addr
        .to_socket_addrs()
        .map(Iterator::collect)
        .unwrap_or_default();
    let mut server = serve_net::Server::builder();
    if addrs.is_empty() {
        // Resolves to nothing: serve-net's validation names the rule.
        server = server.listener(serve_net::ListenerSpec::tcp(
            "web-0",
            &[] as &[std::net::SocketAddr],
        ));
    }
    for (i, a) in addrs.iter().enumerate() {
        server = server.listener(serve_net::ListenerSpec::tcp(
            &format!("web-{i}"),
            std::slice::from_ref(a),
        ));
    }
    server.serve(service)
}

impl<G: Gate, E: Render> fmt::Debug for App<G, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("App")
            .field("site", &self.site)
            .field("base", &self.shared.base)
            .field("routes", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Whether the client prefers JSON to HTML (no `Accept`: HTML).
fn wants_json(accept: Option<&[u8]>) -> bool {
    // Most requests never name JSON: skip the parse for them.
    accept.is_some_and(|a| a.windows(4).any(|w| w.eq_ignore_ascii_case(b"json")))
        && parse_net::best_media(accept, &["text/html", "application/json"]) == Some(1)
}

/// gzip for a reply worth compressing that the client accepts. Adds `Vary`
/// for every compressible reply, compressed or not, so caches keep the two
/// apart.
fn compress(c: Compression, accept_encoding: Option<&[u8]>, out: &mut Out) {
    if out.status != 200 || out.has("content-encoding") {
        return;
    }
    if !out.get("content-type").is_some_and(compressible) {
        return;
    }
    // The handler's own `Vary` keeps its names and gains this one, so a
    // cache keyed on them never hands a compressed body to a client that
    // did not accept it.
    match out.get("vary") {
        None => out.header("vary", b"accept-encoding"),
        Some(v) => {
            let named = v == b"*"
                || v.split(|&b| b == b',')
                    .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"accept-encoding"));
            if !named {
                let mut joined = v.to_vec();
                joined.extend_from_slice(b", accept-encoding");
                out.remove("vary");
                out.header("vary", &joined);
            }
        }
    }
    let accepts = accept_encoding
        .and_then(|v| parse_net::best_encoding(Some(v), &["gzip", "identity"]))
        == Some(0);
    if !accepts || out.body.len() < c.min_bytes {
        return;
    }
    let level = compress_lib::Level::new(c.level).unwrap_or(compress_lib::Level::DEFAULT);
    let packed = compress_lib::gzip::compress_with(&out.body, level);
    if packed.len() < out.body.len() {
        out.body.clear();
        out.body.extend_from_slice(&packed);
        out.header("content-encoding", b"gzip");
    }
}

/// Percent-encodes a query component: everything but unreserved and `/`.
fn encode_component(s: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_port() {
        assert_eq!(split_port("a.test:80"), ("a.test", Some("80")));
        assert_eq!(split_port("a.test"), ("a.test", None));
        assert_eq!(split_port("[::1]:8080"), ("[::1]", Some("8080")));
        assert_eq!(split_port("[::1]"), ("[::1]", None));
    }

    #[test]
    fn test_valid_host() {
        for ok in ["example.com", "localhost:8080", "[::1]", "127.0.0.1:80"] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in ["", "a b", "a:", "a:x", "[zz]", "a/b"] {
            assert!(!valid_host(bad), "{bad}");
        }
    }

    #[test]
    fn test_selector() {
        assert!(Routes::prefix("/blog").matches("/blog", None));
        assert!(Routes::prefix("/blog/").matches("/blog/:slug", None));
        assert!(!Routes::prefix("/blog").matches("/blogger", None));
        assert!(Routes::named(&["a"]).matches("/x", Some("a")));
        assert!(!Routes::named(&["a"]).matches("/x", None));
    }
}
