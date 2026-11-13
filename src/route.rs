//! Route declarations: a path, its methods and handlers, and its access.

use std::sync::Arc;

use serve_net::{Method, WorkClass};

use crate::{Context, NoRender, Render, Result};

/// A request handler. Any `Fn(&mut Context<'_, I, E>) -> web_net::Result` is one.
///
/// ```
/// use serve_net::Method;
/// use web_net::{App, Context, Handler, Render, Result, Route};
///
/// // A handler that carries its own data.
/// struct Greeting(&'static str);
/// impl<I, E: Render> Handler<I, E> for Greeting {
///     fn call(&self, cx: &mut Context<'_, I, E>) -> Result {
///         cx.text(200, self.0)
///     }
/// }
///
/// let app = App::builder().route(Route::at("/").on(Method::Get, Greeting("hello"))).build()?;
/// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.text(), "hello");
/// # Ok::<(), web_net::BuildError>(())
/// ```
pub trait Handler<I, E: Render = NoRender>: Send + Sync + 'static {
    /// Handles one cleared request.
    ///
    /// # Errors
    ///
    /// An [`Error`](crate::Error), answered with the site's error page for
    /// its status.
    fn call(&self, cx: &mut Context<'_, I, E>) -> Result;
}

impl<I, E: Render, F> Handler<I, E> for F
where
    F: Fn(&mut Context<'_, I, E>) -> Result + Send + Sync + 'static,
{
    #[inline]
    fn call(&self, cx: &mut Context<'_, I, E>) -> Result {
        self(cx)
    }
}

/// Who may use a route.
#[derive(Debug)]
pub(crate) enum Access<R> {
    /// Not declared: the build refuses the route.
    Undeclared,
    /// Anyone, guests included; the gate's `authorize` is not called.
    Public,
    /// Those every rule allows: the groups' rules, outermost first, then the
    /// route's own.
    Rules(Vec<Arc<R>>),
    /// Declared public inside a group with a rule: the build refuses it.
    PublicInRuled,
}

impl<R> Clone for Access<R> {
    fn clone(&self) -> Self {
        match self {
            Self::Undeclared => Self::Undeclared,
            Self::Public => Self::Public,
            Self::Rules(r) => Self::Rules(r.clone()),
            Self::PublicInRuled => Self::PublicInRuled,
        }
    }
}

impl<R> Access<R> {
    /// This access for a route inside a group whose access is `outer`: a
    /// group's rule always holds, and a route's own rule adds to it.
    fn within(self, outer: &Self) -> Self {
        match (outer, self) {
            (Self::Rules(o), Self::Undeclared) => Self::Rules(o.clone()),
            (Self::Rules(o), Self::Rules(own)) => {
                Self::Rules(o.iter().cloned().chain(own).collect())
            }
            (Self::Rules(_), Self::Public | Self::PublicInRuled) => Self::PublicInRuled,
            (Self::Public, Self::Undeclared) => Self::Public,
            (_, own) => own,
        }
    }
}

pub(crate) type BoxHandler<I, E> = Arc<dyn Handler<I, E>>;

/// A route: a path pattern, one handler per method, and who may use it.
///
/// Patterns are made of literal segments, parameters (`:id`, one segment)
/// and one wildcard at the end (`*rest`, the rest of the path). Literals are
/// written decoded (`/café`); web-net compares them with the canonical
/// request path.
///
/// ```
/// use web_net::{App, get, Route};
///
/// let app = App::builder()
///     .route(get("/", |cx| cx.html(200, "<h1>Home</h1>")))
///     .route(
///         Route::at("/contact")
///             .get(|cx| cx.html(200, "<form method=post></form>"))
///             .post(|cx| cx.redirect(303, "/contact/thanks"))
///             // A real form gets CSRF protection: Builder::csrf and a gate
///             // whose identities carry a binding.
///             .csrf_exempt("example: the POST changes nothing"),
///     )
///     .build()?;
/// # Ok::<(), web_net::BuildError>(())
/// ```
///
/// A closure that reads fields of a custom identity types its parameter,
/// because the closure is checked before the builder fixes the type (a
/// named `fn` handler needs nothing extra):
///
/// ```
/// use web_net::{Context, Route, get};
///
/// struct User { name: String }
/// impl web_net::Identity for User {
///     fn is_guest(&self) -> bool { self.name.is_empty() }
/// }
/// enum Rule { SignedIn }
///
/// let account: Route<User, Rule> = get("/account", |cx: &mut Context<'_, User>| {
///     let name = cx.identity().name.clone();
///     cx.text(200, &name)
/// })
/// .allow(Rule::SignedIn);
/// # let _ = account;
/// ```
pub struct Route<I, R, E: Render = NoRender> {
    pub(crate) pattern: String,
    pub(crate) handlers: Vec<(Method, BoxHandler<I, E>)>,
    pub(crate) access: Access<R>,
    pub(crate) name: Option<&'static str>,
    pub(crate) work: WorkClass,
    pub(crate) template: Option<&'static str>,
    pub(crate) csrf_exempt: Option<&'static str>,
    pub(crate) form_limits: form_net::Limits,
    pub(crate) cors: Option<Arc<crate::Cors>>,
    pub(crate) cache: crate::CachePolicy,
}

impl<I: 'static, R, E: Render> Route<I, R, E> {
    /// A route at `pattern` with no methods yet.
    ///
    /// ```
    /// use web_net::{App, Route};
    ///
    /// let app = App::builder()
    ///     .route(Route::at("/about").get(|cx| cx.text(200, "about")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /about HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "about");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn at(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            handlers: Vec::new(),
            access: Access::Undeclared,
            name: None,
            work: WorkClass::Quick,
            template: None,
            csrf_exempt: None,
            form_limits: form_net::Limits::DEFAULT,
            cors: None,
            cache: crate::CachePolicy::Unset,
        }
    }

    /// Adds a handler for `method`. `HEAD` follows `GET` unless it has its
    /// own; `OPTIONS` is answered for every route unless it has its own.
    ///
    /// ```
    /// use serve_net::Method;
    /// use web_net::{App, Context, Guest, Route};
    ///
    /// fn store(cx: &mut Context<'_, Guest>) -> web_net::Result {
    ///     cx.text(200, "stored")
    /// }
    ///
    /// let app = App::builder()
    ///     .route(Route::at("/items").on(Method::Put, store).csrf_exempt("example: no browser form"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"PUT /items HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    /// );
    /// assert_eq!(r.text(), "stored");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn on(mut self, method: Method, handler: impl Handler<I, E>) -> Self {
        self.handlers.push((method, Arc::new(handler)));
        self
    }

    /// Adds a `GET` handler.
    ///
    /// ```
    /// use web_net::{App, Route};
    ///
    /// let app = App::builder()
    ///     .route(Route::at("/").get(|cx| cx.text(200, "home")))
    ///     .build()?;
    /// // HEAD follows GET.
    /// let r = serve_net::testing::respond(&app, b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.status, 200);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn get<F>(self, f: F) -> Self
    where
        F: Fn(&mut Context<'_, I, E>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Get, f)
    }

    /// Adds a `POST` handler.
    ///
    /// ```
    /// use web_net::{App, Route};
    ///
    /// let app = App::builder()
    ///     .route(Route::at("/items/:id").post(|cx| cx.text(200, "created")).csrf_exempt("example: no browser form"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"POST /items/1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    /// );
    /// assert_eq!(r.text(), "created");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn post<F>(self, f: F) -> Self
    where
        F: Fn(&mut Context<'_, I, E>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Post, f)
    }

    /// Adds a `PUT` handler.
    ///
    /// ```
    /// use web_net::{App, Route};
    ///
    /// let app = App::builder()
    ///     .route(Route::at("/items/:id").put(|cx| cx.text(200, "replaced")).csrf_exempt("example: no browser form"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"PUT /items/1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    /// );
    /// assert_eq!(r.text(), "replaced");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn put<F>(self, f: F) -> Self
    where
        F: Fn(&mut Context<'_, I, E>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Put, f)
    }

    /// Adds a `PATCH` handler.
    ///
    /// ```
    /// use web_net::{App, Route};
    ///
    /// let app = App::builder()
    ///     .route(Route::at("/items/:id").patch(|cx| cx.text(200, "changed")).csrf_exempt("example: no browser form"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"PATCH /items/1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    /// );
    /// assert_eq!(r.text(), "changed");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn patch<F>(self, f: F) -> Self
    where
        F: Fn(&mut Context<'_, I, E>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Patch, f)
    }

    /// Adds a `DELETE` handler.
    ///
    /// ```
    /// use web_net::{App, Route};
    ///
    /// let app = App::builder()
    ///     .route(Route::at("/items/:id").delete(|cx| cx.text(200, "deleted")).csrf_exempt("example: no browser form"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"DELETE /items/1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    /// );
    /// assert_eq!(r.text(), "deleted");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn delete<F>(self, f: F) -> Self
    where
        F: Fn(&mut Context<'_, I, E>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Delete, f)
    }

    /// Anyone may use the route, guests included. With a gate that has
    /// rules, public is a declaration, never a default: a route with neither
    /// `public` nor `allow` stops the build. With [`Open`](crate::Open),
    /// whose rule type has no values, every route is public and needs
    /// neither.
    ///
    /// ```
    /// use web_net::{App, get};
    /// # use web_net::{Denial, Gate, Guest, Request};
    /// # enum Rule { Staff }
    /// # struct NoStaff;
    /// # impl Gate for NoStaff {
    /// #     type Identity = Guest;
    /// #     type Rule = Rule;
    /// #     fn authenticate(&self, _: &Request<'_>) -> Result<Guest, Denial> { Ok(Guest) }
    /// #     fn authorize(&self, _: &Guest, _: &Rule, _: &Request<'_>) -> Result<(), Denial> {
    /// #         Err(Denial::forbidden("staff.only"))
    /// #     }
    /// # }
    /// // `NoStaff` is a gate that denies `Rule::Staff` to everyone.
    /// let app = App::with_gate(NoStaff)
    ///     .route(get("/", |cx| cx.text(200, "home")).public())
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.status, 200);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn public(mut self) -> Self {
        self.access = Access::Public;
        self
    }

    /// Those `rule` allows may use the route; the gate's `authorize` decides
    /// on every request. Inside a group with a rule, both rules hold: the
    /// group's first, then this one.
    ///
    /// ```
    /// use web_net::{App, get};
    /// # use web_net::{Denial, Gate, Guest, Request};
    /// # enum Rule { Staff }
    /// # struct NoStaff;
    /// # impl Gate for NoStaff {
    /// #     type Identity = Guest;
    /// #     type Rule = Rule;
    /// #     fn authenticate(&self, _: &Request<'_>) -> Result<Guest, Denial> { Ok(Guest) }
    /// #     fn authorize(&self, _: &Guest, _: &Rule, _: &Request<'_>) -> Result<(), Denial> {
    /// #         Err(Denial::forbidden("staff.only"))
    /// #     }
    /// # }
    /// // `NoStaff` is a gate that denies `Rule::Staff` to everyone.
    /// let app = App::with_gate(NoStaff)
    ///     .route(get("/admin", |cx| cx.text(200, "admin")).allow(Rule::Staff))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.status, 403);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn allow(mut self, rule: R) -> Self {
        self.access = Access::Rules(vec![Arc::new(rule)]);
        self
    }

    /// A name for logs, events, and hooks.
    ///
    /// ```
    /// use web_net::{App, Hook, Routes, get};
    ///
    /// let app = App::builder()
    ///     .hook(Hook::Finish, Routes::named(&["home"]), |cx| {
    ///         cx.set_header("x-page", "home");
    ///         Ok(())
    ///     })
    ///     .route(get("/", |cx| cx.text(200, "home")).name("home"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("x-page"), Some(&b"home"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn name(mut self, name: &'static str) -> Self {
        self.name = Some(name);
        self
    }

    /// How the handlers behave: `Quick` (the default), `Io`, or `Cpu`. A
    /// dispatcher in front of web-net reads it through
    /// [`App::classify`](crate::App::classify) to move slow work off the
    /// connection's worker.
    ///
    /// ```
    /// use serve_net::WorkClass;
    /// use web_net::{App, get};
    ///
    /// // The report waits on a database: a dispatcher can run it off the
    /// // connection's worker.
    /// let app = App::builder()
    ///     .route(get("/report", |cx| cx.text(200, "report")).work(WorkClass::Io))
    ///     .build()?;
    /// # let _ = app;
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn work(mut self, work: WorkClass) -> Self {
        self.work = work;
        self
    }

    /// Takes the route out of CSRF protection, with the reason (a webhook
    /// signed by its sender, an API authenticated by a bearer token that a
    /// browser never sends on its own). The reason is required and must not
    /// be empty: an exemption is a decision, never a default.
    ///
    /// ```
    /// use web_net::{App, post};
    ///
    /// let app = App::builder()
    ///     .route(post("/hooks/build", |cx| cx.text(200, "queued")).csrf_exempt("signed by the CI server"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"POST /hooks/build HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    /// );
    /// assert_eq!(r.text(), "queued");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn csrf_exempt(mut self, reason: &'static str) -> Self {
        self.csrf_exempt = Some(reason);
        self
    }

    /// The budgets for reading this route's forms (field count, sizes, files;
    /// default `form_net::Limits::DEFAULT`). Keep them to what the form
    /// needs: they bound what one request can make the server hold.
    ///
    /// ```
    /// use web_net::{App, form_net, post};
    ///
    /// let limits = form_net::Limits::DEFAULT.with_max_fields(4);
    /// let app = App::builder()
    ///     .route(
    ///         post("/search", |cx| cx.text(200, "results"))
    ///             .form_limits(limits)
    ///             .csrf_exempt("example: changes nothing"),
    ///     )
    ///     .build()?;
    /// # let _ = app;
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn form_limits(mut self, limits: form_net::Limits) -> Self {
        self.form_limits = limits;
        self
    }

    /// The route's CORS policy: preflights answered, replies to allowed
    /// origins readable by their scripts.
    ///
    /// ```
    /// use web_net::{App, Cors, get};
    ///
    /// let app = App::builder()
    ///     .route(
    ///         get("/api/items", |cx| cx.bytes(200, "application/json", b"[]"))
    ///             .cors(Cors::new().origin("https://app.example.com")),
    ///     )
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"GET /api/items HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\n\r\n",
    /// );
    /// assert_eq!(r.header("access-control-allow-origin"), Some(&b"https://app.example.com"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn cors(mut self, cors: crate::Cors) -> Self {
        self.cors = Some(Arc::new(cors));
        self
    }

    /// How the route's pages may be cached.
    ///
    /// ```
    /// use web_net::{App, CachePolicy, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/account", |cx| cx.text(200, "yours")).cache(CachePolicy::NoStore))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /account HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("cache-control"), Some(&b"no-store"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn cache(mut self, policy: crate::CachePolicy) -> Self {
        self.cache = policy;
        self
    }

    /// The template [`Context::render`](crate::Context::render) uses. Resolved when the
    /// application is built: an unknown name stops the build.
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
    ///     .route(get("/", |cx: &mut Context<'_, Guest, Pages>| cx.render("Home")).template("page"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "Home");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn template(mut self, name: &'static str) -> Self {
        self.template = Some(name);
        self
    }
}

impl<I, R, E: Render> std::fmt::Debug for Route<I, R, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("pattern", &self.pattern)
            .field(
                "methods",
                &self.handlers.iter().map(|(m, _)| *m).collect::<Vec<_>>(),
            )
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

macro_rules! method_fn {
    ($(#[$doc:meta])* $fn:ident, $m:ident) => {
        $(#[$doc])*
        #[must_use]
        pub fn $fn<I: 'static, R, E: Render, F>(pattern: impl Into<String>, f: F) -> Route<I, R, E>
        where
            F: Fn(&mut Context<'_, I, E>) -> Result + Send + Sync + 'static,
        {
            Route::at(pattern).on(Method::$m, f)
        }
    };
}

method_fn! {
    /// A route with a `GET` handler (and so `HEAD`).
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder().route(get("/", |cx| cx.text(200, "home"))).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "home");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    get, Get
}
method_fn! {
    /// A route with a `POST` handler.
    ///
    /// ```
    /// use web_net::{App, post};
    ///
    /// let app = App::builder()
    ///     .route(post("/items/:id", |cx| cx.text(200, "created")).csrf_exempt("example: no browser form"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"POST /items/1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    /// );
    /// assert_eq!(r.text(), "created");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    post, Post
}
method_fn! {
    /// A route with a `PUT` handler.
    ///
    /// ```
    /// use web_net::{App, put};
    ///
    /// let app = App::builder()
    ///     .route(put("/items/:id", |cx| cx.text(200, "replaced")).csrf_exempt("example: no browser form"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"PUT /items/1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    /// );
    /// assert_eq!(r.text(), "replaced");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    put, Put
}
method_fn! {
    /// A route with a `PATCH` handler.
    ///
    /// ```
    /// use web_net::{App, patch};
    ///
    /// let app = App::builder()
    ///     .route(patch("/items/:id", |cx| cx.text(200, "changed")).csrf_exempt("example: no browser form"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"PATCH /items/1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    /// );
    /// assert_eq!(r.text(), "changed");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    patch, Patch
}
method_fn! {
    /// A route with a `DELETE` handler.
    ///
    /// ```
    /// use web_net::{App, delete};
    ///
    /// let app = App::builder()
    ///     .route(delete("/items/:id", |cx| cx.text(200, "deleted")).csrf_exempt("example: no browser form"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"DELETE /items/1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    /// );
    /// assert_eq!(r.text(), "deleted");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    delete, Delete
}

/// Routes sharing a path prefix and an access boundary.
///
/// A group's rule holds for every route in it: a route's own rule adds to
/// it (both are checked, the group's first), and a route declared public
/// inside a group with a rule stops the build. A route that declares
/// nothing takes the group's access.
///
/// ```
/// use web_net::{App, Group, get};
///
/// let app = App::builder()
///     .group(
///         Group::at("/docs")
///             .route(get("/", |cx| cx.text(200, "index")))
///             .route(get("/:page", |cx| cx.text(200, "page"))),
///     )
///     .build()?;
/// # Ok::<(), web_net::BuildError>(())
/// ```
pub struct Group<I, R, E: Render = NoRender> {
    pub(crate) prefix: String,
    pub(crate) access: Access<R>,
    pub(crate) routes: Vec<Route<I, R, E>>,
    pub(crate) cors: Option<Arc<crate::Cors>>,
    pub(crate) cache: crate::CachePolicy,
}

impl<I: 'static, R, E: Render> Group<I, R, E> {
    /// A group under `prefix` (`/admin`).
    ///
    /// ```
    /// use web_net::{App, Group, get};
    ///
    /// let app = App::builder()
    ///     .group(Group::at("/admin").route(get("/", |cx| cx.text(200, "dashboard"))))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "dashboard");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn at(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            access: Access::Undeclared,
            routes: Vec::new(),
            cors: None,
            cache: crate::CachePolicy::Unset,
        }
    }

    /// The CORS policy of routes that declare none.
    ///
    /// ```
    /// use web_net::{App, Cors, Group, get};
    ///
    /// let api = Group::at("/api")
    ///     .cors(Cors::new().origin("https://app.example.com"))
    ///     .route(get("/items", |cx| cx.bytes(200, "application/json", b"[]")));
    /// let app = App::builder().group(api).build()?;
    /// let r = serve_net::testing::respond(
    ///     &app,
    ///     b"GET /api/items HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\n\r\n",
    /// );
    /// assert_eq!(r.header("access-control-allow-origin"), Some(&b"https://app.example.com"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn cors(mut self, cors: crate::Cors) -> Self {
        self.cors = Some(Arc::new(cors));
        self
    }

    /// The cache policy of routes that declare none.
    ///
    /// ```
    /// use web_net::{App, CachePolicy, Group, get};
    ///
    /// let docs = Group::at("/docs")
    ///     .cache(CachePolicy::Guests { max_age: 60 })
    ///     .route(get("/intro", |cx| cx.text(200, "intro")));
    /// let app = App::builder().group(docs).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /docs/intro HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("cache-control"), Some(&b"public, max-age=60"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn cache(mut self, policy: crate::CachePolicy) -> Self {
        self.cache = policy;
        self
    }

    /// Routes that declare nothing are public.
    ///
    /// ```
    /// use web_net::{App, Group, get};
    /// # use web_net::{Denial, Gate, Guest, Request};
    /// # enum Rule { Staff }
    /// # struct NoStaff;
    /// # impl Gate for NoStaff {
    /// #     type Identity = Guest;
    /// #     type Rule = Rule;
    /// #     fn authenticate(&self, _: &Request<'_>) -> Result<Guest, Denial> { Ok(Guest) }
    /// #     fn authorize(&self, _: &Guest, _: &Rule, _: &Request<'_>) -> Result<(), Denial> {
    /// #         Err(Denial::forbidden("staff.only"))
    /// #     }
    /// # }
    /// // `NoStaff` is a gate that denies `Rule::Staff` to everyone.
    /// let app = App::with_gate(NoStaff)
    ///     .group(Group::at("/docs").public().route(get("/intro", |cx| cx.text(200, "intro"))))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /docs/intro HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.status, 200);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn public(mut self) -> Self {
        self.access = Access::Public;
        self
    }

    /// Every route in the group needs `rule`, as well as its own.
    ///
    /// ```
    /// use web_net::{App, Group, get};
    /// # use web_net::{Denial, Gate, Guest, Request};
    /// # enum Rule { Staff }
    /// # struct NoStaff;
    /// # impl Gate for NoStaff {
    /// #     type Identity = Guest;
    /// #     type Rule = Rule;
    /// #     fn authenticate(&self, _: &Request<'_>) -> Result<Guest, Denial> { Ok(Guest) }
    /// #     fn authorize(&self, _: &Guest, _: &Rule, _: &Request<'_>) -> Result<(), Denial> {
    /// #         Err(Denial::forbidden("staff.only"))
    /// #     }
    /// # }
    /// // `NoStaff` is a gate that denies `Rule::Staff` to everyone.
    /// let app = App::with_gate(NoStaff)
    ///     .group(Group::at("/admin").allow(Rule::Staff).route(get("/users", |cx| cx.text(200, "users"))))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /admin/users HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.status, 403);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn allow(mut self, rule: R) -> Self {
        self.access = Access::Rules(vec![Arc::new(rule)]);
        self
    }

    /// Adds a route; its pattern is joined to the prefix.
    ///
    /// ```
    /// use web_net::{App, Group, get};
    ///
    /// let blog = Group::at("/blog").route(get("/:slug", |cx| {
    ///     let slug: String = cx.param_as("slug")?;
    ///     cx.text(200, &slug)
    /// }));
    /// let app = App::builder().group(blog).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /blog/hello HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "hello");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn route(mut self, route: Route<I, R, E>) -> Self {
        self.routes.push(route);
        self
    }

    /// Adds a nested group; its prefix is joined to this one, and its
    /// access holds inside this group's (both rules apply).
    ///
    /// ```
    /// use web_net::{App, Group, get};
    ///
    /// let v1 = Group::at("/v1").route(get("/items", |cx| cx.text(200, "items")));
    /// let app = App::builder().group(Group::at("/api").group(v1)).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /api/v1/items HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "items");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn group(mut self, group: Group<I, R, E>) -> Self {
        let inherited = group.access.within(&self.access);
        let cors = group.cors.or_else(|| self.cors.clone());
        let cache = if group.cache == crate::CachePolicy::Unset {
            self.cache
        } else {
            group.cache
        };
        for mut r in group.routes {
            r.pattern = join(&group.prefix, &r.pattern);
            r.access = std::mem::replace(&mut r.access, Access::Undeclared).within(&inherited);
            if r.cors.is_none() {
                r.cors.clone_from(&cors);
            }
            if r.cache == crate::CachePolicy::Unset {
                r.cache = cache;
            }
            self.routes.push(r);
        }
        self
    }

    pub(crate) fn into_routes(self) -> impl Iterator<Item = Route<I, R, E>> {
        let prefix = self.prefix;
        let access = self.access;
        let cors = self.cors;
        let cache = self.cache;
        self.routes.into_iter().map(move |mut r| {
            r.pattern = join(&prefix, &r.pattern);
            r.access = std::mem::replace(&mut r.access, Access::Undeclared).within(&access);
            if r.cors.is_none() {
                r.cors.clone_from(&cors);
            }
            if r.cache == crate::CachePolicy::Unset {
                r.cache = cache;
            }
            r
        })
    }
}

impl<I, R, E: Render> std::fmt::Debug for Group<I, R, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group")
            .field("prefix", &self.prefix)
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

/// `/admin` + `/` = `/admin`; `/admin` + `/users` = `/admin/users`.
pub(crate) fn join(prefix: &str, pattern: &str) -> String {
    let p = prefix.trim_end_matches('/');
    if pattern == "/" || pattern.is_empty() {
        if p.is_empty() { "/".into() } else { p.into() }
    } else if pattern.starts_with('/') {
        format!("{p}{pattern}")
    } else {
        format!("{p}/{pattern}")
    }
}

#[cfg(test)]
mod tests {
    use super::join;

    #[test]
    fn test_join() {
        assert_eq!(join("/admin", "/"), "/admin");
        assert_eq!(join("/admin/", "/users"), "/admin/users");
        assert_eq!(join("/", "/x"), "/x");
        assert_eq!(join("", "/"), "/");
        assert_eq!(join("/a", "b"), "/a/b");
    }
}
