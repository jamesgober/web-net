//! Several sites in one server: the host and the base path pick the
//! application.

use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};

use crate::{App, Gate, Open, Served};

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
///     .route(get("/", |cx| { cx.text(200, "blog"); Ok(()) }).public())
///     .build()?;
/// let shop = App::builder()
///     .host("shop.example.com")
///     .route(get("/", |cx| { cx.text(200, "shop"); Ok(()) }).public())
///     .build()?;
/// let main = App::builder()
///     .host("example.com")
///     .route(get("/", |cx| { cx.text(200, "home"); Ok(()) }).public())
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
pub struct Sites<G: Gate = Open> {
    apps: Vec<App<G>>,
}

impl<G: Gate> Default for Sites<G> {
    fn default() -> Self {
        Self { apps: Vec::new() }
    }
}

impl<G: Gate> Sites<G> {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an application. The first one added answers what no other
    /// claims.
    #[must_use]
    pub fn site(mut self, app: App<G>) -> Self {
        self.apps.push(app);
        self
    }

    /// The application for a request, if the table has any.
    #[must_use]
    pub fn pick(&self, req: &HttpRequest<'_>) -> Option<&App<G>> {
        let authority = req.head().authority();
        let path = req.path();
        self.apps
            .iter()
            .filter_map(|a| a.claim(authority, path).map(|score| (score, a)))
            .max_by_key(|(score, _)| *score)
            .map(|(_, a)| a)
            .or_else(|| self.apps.first())
    }

    /// As [`App::serve`] on the chosen application.
    pub fn serve(
        &self,
        req: &HttpRequest<'_>,
        env: &Envelope,
        who: Option<&G::Identity>,
        reply: &mut HttpReply,
    ) -> Served {
        match self.pick(req) {
            Some(app) => app.serve(req, env, who, reply),
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

impl<G: Gate> HttpService for Sites<G> {
    fn call(&self, request: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        self.serve(request, env, None, reply).outcome
    }
}

impl<G: Gate> std::fmt::Debug for Sites<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sites").field("apps", &self.apps).finish()
    }
}
