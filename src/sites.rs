//! Several sites in one server: the host and the base path pick the
//! application.

use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};

use crate::{App, Gate, NoRender, Open, Render, Served};

/// A table of applications, chosen per request by host and base path: an
/// application that lists the request's host (or an alias of it) wins over
/// one that answers any host, and among those, the longest base path that
/// holds the request's path. A request no application claims goes to the
/// first one added, which answers it by its own rules (421 for a host it
/// does not serve, 404 outside its base).
///
/// ```
/// use web_net::{App, Sites, get};
///
/// let blog = App::builder()
///     .host("example.com")
///     .base("/blog")
///     .route(get("/", |cx| cx.text(200, "blog")))
///     .build()?;
/// let shop = App::builder()
///     .host("shop.example.com")
///     .route(get("/", |cx| cx.text(200, "shop")))
///     .build()?;
/// let main = App::builder()
///     .host("example.com")
///     .route(get("/", |cx| cx.text(200, "home")))
///     .build()?;
/// let sites = Sites::new().site(main).site(blog).site(shop);
///
/// use serve_net::testing::respond;
/// assert_eq!(respond(&sites, b"GET /blog/ HTTP/1.1\r\nHost: example.com\r\n\r\n").text(), "blog");
/// assert_eq!(respond(&sites, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").text(), "home");
/// assert_eq!(respond(&sites, b"GET / HTTP/1.1\r\nHost: shop.example.com\r\n\r\n").text(), "shop");
/// assert_eq!(respond(&sites, b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n").status, 421);
/// # Ok::<(), web_net::BuildError>(())
/// ```
pub struct Sites<G: Gate = Open, E: Render = NoRender> {
    apps: Vec<App<G, E>>,
}

impl<G: Gate, E: Render> Default for Sites<G, E> {
    fn default() -> Self {
        Self { apps: Vec::new() }
    }
}

impl<G: Gate, E: Render> Sites<G, E> {
    /// An empty table.
    ///
    /// ```
    /// use web_net::Sites;
    ///
    /// // With no application, every request is answered with 421.
    /// let sites: Sites = Sites::new();
    /// let r = serve_net::testing::respond(&sites, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.status, 421);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an application. The first one added answers what no other
    /// claims.
    ///
    /// ```
    /// use serve_net::testing::respond;
    /// use web_net::{App, Sites, get};
    ///
    /// let main = App::builder().host("example.com").route(get("/", |cx| cx.text(200, "home"))).build()?;
    /// let shop = App::builder().host("shop.example.com").route(get("/", |cx| cx.text(200, "shop"))).build()?;
    /// let sites = Sites::new().site(main).site(shop);
    /// assert_eq!(respond(&sites, b"GET / HTTP/1.1\r\nHost: shop.example.com\r\n\r\n").text(), "shop");
    /// assert_eq!(respond(&sites, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").text(), "home");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn site(mut self, app: App<G, E>) -> Self {
        self.apps.push(app);
        self
    }

    /// The application for a request, if the table has any.
    ///
    /// ```
    /// use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};
    /// use web_net::{App, Sites, get};
    ///
    /// // A front that picks the application itself before it answers.
    /// struct Front(Sites);
    /// impl HttpService for Front {
    ///     fn call(&self, req: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
    ///         let app = self.0.pick(req).expect("one site is configured");
    ///         app.respond(req, env, None, reply).outcome
    ///     }
    /// }
    ///
    /// let shop = App::builder().host("shop.example.com").route(get("/", |cx| cx.text(200, "shop"))).build()?;
    /// let front = Front(Sites::new().site(shop));
    /// let r = serve_net::testing::respond(&front, b"GET / HTTP/1.1\r\nHost: shop.example.com\r\n\r\n");
    /// assert_eq!(r.text(), "shop");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn pick(&self, req: &HttpRequest<'_>) -> Option<&App<G, E>> {
        let authority = req.head().authority();
        let path = req.path();
        self.apps
            .iter()
            .filter_map(|a| a.claim(authority, path).map(|score| (score, a)))
            .max_by_key(|(score, _)| *score)
            .map(|(_, a)| a)
            .or_else(|| self.apps.first())
    }

    /// Serves every site on `addr`, as [`App::listen`] does for one.
    ///
    /// # Errors
    ///
    /// As [`App::listen`].
    ///
    /// ```no_run
    /// use web_net::{App, Sites, get};
    ///
    /// let main = App::builder().host("example.com").route(get("/", |cx| cx.text(200, "home"))).build()?;
    /// let shop = App::builder().host("shop.example.com").route(get("/", |cx| cx.text(200, "shop"))).build()?;
    /// Sites::new().site(main).site(shop).listen("127.0.0.1:8080")?.wait();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn listen(
        self,
        addr: impl std::net::ToSocketAddrs,
    ) -> std::result::Result<serve_net::Running, serve_net::ServeError> {
        crate::app::listen(addr, self)
    }

    /// As [`App::respond`] on the chosen application.
    ///
    /// ```
    /// use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};
    /// use web_net::{App, Guest, Sites, get};
    ///
    /// // A front that authenticated every request already.
    /// struct Front(Sites);
    /// impl HttpService for Front {
    ///     fn call(&self, req: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
    ///         self.0.respond(req, env, Some(&Guest), reply).outcome
    ///     }
    /// }
    ///
    /// let app = App::builder().route(get("/", |cx| cx.text(200, "hi"))).build()?;
    /// let r = serve_net::testing::respond(&Front(Sites::new().site(app)), b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
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
        match self.pick(req) {
            Some(app) => app.respond(req, env, who, reply),
            None => {
                reply.text(421, "no site is configured");
                Served {
                    outcome: Outcome::Done,
                    route: None,
                    cache: crate::Cacheable::No,
                }
            }
        }
    }
}

impl<G: Gate, E: Render> HttpService for Sites<G, E> {
    fn call(&self, request: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        self.respond(request, env, None, reply).outcome
    }

    fn done(&self, env: &Envelope, _finished: &serve_net::Finished) {
        for app in &self.apps {
            app.forget(env);
        }
    }
}

impl<G: Gate, E: Render> std::fmt::Debug for Sites<G, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sites").field("apps", &self.apps).finish()
    }
}
