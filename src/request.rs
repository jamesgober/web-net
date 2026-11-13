//! The request as gates and handlers read it.

use std::fmt;

use serve_net::{ClientInfo, Envelope, HttpRequest, Method, Scheme};

/// A request's reference: shown on error pages and carried by every event,
/// so a visitor's report finds the log line.
///
/// It displays as 16 hexadecimal digits, a keyed hash of the connection id
/// and the request's number with a key made at start-up: the same request
/// always shows the same reference in one process, and two references say
/// nothing about how much traffic came between them (the raw counters
/// would). [`connection`](Self::connection) and [`seq`](Self::seq) give the
/// raw values for the logs. Not a security token.
///
/// ```
/// use web_net::{App, get};
///
/// let app = App::builder().route(get("/", |cx| cx.text(200, &cx.id().to_string()))).build()?;
/// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.text().len(), 16);
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestId {
    connection: u64,
    seq: u32,
}

impl RequestId {
    pub(crate) fn of(env: &Envelope) -> Self {
        Self {
            connection: env.connection().get(),
            seq: env.seq().get(),
        }
    }

    /// The connection id.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let connection = cx.id().connection().to_string();
    ///         cx.text(200, &connection)
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert!(r.text().parse::<u64>().is_ok());
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub const fn connection(&self) -> u64 {
        self.connection
    }

    /// The request's number on its connection.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let seq = cx.id().seq().to_string();
    ///         cx.text(200, &seq)
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "1"); // the first request on its connection
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub const fn seq(&self) -> u32 {
        self.seq
    }
}

/// The process's key for references, made once from the standard
/// library's randomly keyed hasher.
fn reference_key() -> &'static std::collections::hash_map::RandomState {
    static KEY: std::sync::OnceLock<std::collections::hash_map::RandomState> =
        std::sync::OnceLock::new();
    KEY.get_or_init(std::collections::hash_map::RandomState::new)
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::hash::BuildHasher;
        let h = reference_key().hash_one((self.connection, self.seq));
        write!(f, "{h:016x}")
    }
}

/// A `Cookie` field held the name more than once, or the request carried
/// more than one `Cookie` field. A gate treats this as no credential, or as
/// an attack; it never picks one of the values.
///
/// ```
/// use web_net::{Ambiguous, App, get};
///
/// let app = App::builder()
///     .route(get("/", |cx| match cx.request().cookie("sid") {
///         Err(Ambiguous) => cx.text(400, "sid appears twice"),
///         Ok(sid) => cx.text(200, sid.unwrap_or("none")),
///     }))
///     .build()?;
/// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\nCookie: sid=a; sid=b\r\n\r\n");
/// assert_eq!(r.status, 400);
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ambiguous;

impl fmt::Display for Ambiguous {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the cookie appears more than once")
    }
}

impl std::error::Error for Ambiguous {}

/// The request as gates and handlers read it: the parts web-net has checked
/// (the host matched a site, the path is canonical) and the raw request
/// underneath.
///
/// ```
/// use web_net::{App, get};
///
/// let app = App::builder()
///     .route(get("/", |cx| {
///         let req = cx.request();
///         let line = format!("{} {}", req.host(), req.path());
///         cx.text(200, &line)
///     }))
///     .build()?;
/// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.text(), "localhost /");
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[derive(Clone, Copy)]
pub struct Request<'r> {
    pub(crate) http: &'r HttpRequest<'r>,
    pub(crate) env: &'r Envelope,
    pub(crate) path: &'r str,
    pub(crate) host: &'r str,
    pub(crate) route: Option<&'r str>,
    pub(crate) tls: bool,
    pub(crate) json: bool,
}

impl<'r> Request<'r> {
    /// The method.
    ///
    /// ```
    /// use serve_net::Method;
    /// use web_net::{App, post};
    ///
    /// let app = App::builder()
    ///     .route(post("/", |cx| {
    ///         let post = cx.request().method() == Method::Post;
    ///         cx.text(200, if post { "post" } else { "other" })
    ///     }).csrf_exempt("example"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    /// assert_eq!(r.text(), "post");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn method(&self) -> Method {
        self.http.method()
    }

    /// The canonical path inside the site: the base path removed, percent
    /// escapes in their one canonical form. `/` for the site root.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .base("/app")
    ///     .route(get("/about", |cx| cx.text(200, cx.request().path())))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /app/about HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "/about");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn path(&self) -> &'r str {
        self.path
    }

    /// The query after `?`, as received (validated by the parser, not
    /// decoded).
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/search", |cx| cx.text(200, cx.request().query().unwrap_or(""))))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /search?q=red+shoes HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "q=red+shoes"); // not decoded
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn query(&self) -> Option<&'r str> {
        self.http.query()
    }

    /// The host the request named, as received (empty for an HTTP/1.0
    /// request without one). It matched one of the site's hosts, unless the
    /// site accepts any host.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| cx.text(200, cx.request().host())))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "localhost");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn host(&self) -> &'r str {
        self.host
    }

    /// The first value of a field.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let accept = cx.request().header("accept").unwrap_or(b"*/*");
    ///         cx.bytes(200, "text/plain", accept)
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: text/html\r\n\r\n");
    /// assert_eq!(r.text(), "text/html");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&'r [u8]> {
        self.http.header(name)
    }

    /// The first value of a field, if it is UTF-8.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let agent = cx.request().header_str("user-agent").unwrap_or("unknown");
    ///         cx.text(200, agent)
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: demo/1\r\n\r\n");
    /// assert_eq!(r.text(), "demo/1");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn header_str(&self, name: &str) -> Option<&'r str> {
        self.http
            .header(name)
            .and_then(|v| core::str::from_utf8(v).ok())
    }

    /// The value of the cookie `name`, read with cookie-net. `Ok(None)` when
    /// there is no such cookie.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let theme = cx.request().cookie("theme").ok().flatten().unwrap_or("light");
    ///         cx.text(200, theme)
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\nCookie: theme=dark\r\n\r\n");
    /// assert_eq!(r.text(), "dark");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Ambiguous`] when the name appears twice, in one `Cookie` field or
    /// across several (a sign of cookie tossing, never resolved by picking
    /// one), or when the fields together are longer than cookie-net's
    /// limit. Several `Cookie` fields are read as one header: HTTP/2 and
    /// HTTP/3 send the cookie as crumbs (RFC 9113 section 8.2.3).
    pub fn cookie(&self, name: &str) -> Result<Option<&'r str>, Ambiguous> {
        let mut found = None;
        let mut total = 0usize;
        for field in self.http.head().header_all("cookie") {
            total = total.saturating_add(field.len());
            if total > cookie_net::Limits::DEFAULT.header_len() {
                return Err(Ambiguous);
            }
            match cookie_net::get_unique(field, name) {
                Ok(None) => {}
                Ok(Some(v)) if found.is_none() => found = Some(v),
                // In two fields, or twice in one.
                Ok(Some(_)) | Err(_) => return Err(Ambiguous),
            }
        }
        Ok(found)
    }

    /// The client, as serve-net established it (the real address behind a
    /// trusted proxy).
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let ip = cx.request().client().addr().map(|a| a.to_string()).unwrap_or_default();
    ///         cx.text(200, &ip)
    ///     }))
    ///     .build()?;
    /// // serve-net's test client connects from 127.0.0.1.
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "127.0.0.1");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn client(&self) -> &'r ClientInfo {
        self.env.client()
    }

    /// `https` when the request came over TLS (or from a trusted proxy that
    /// said so).
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| cx.text(200, cx.request().scheme().as_str())))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "http");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.env.client().scheme()
    }

    /// The TLS handshake, when serve-net decrypted the connection itself:
    /// the server name the client asked for, the negotiated protocol, the
    /// version and cipher suite, and the SHA-256 of a verified client
    /// certificate's public key. `None` over plain HTTP and behind a front
    /// that decrypted. serve-net has already refused a request whose `Host`
    /// names another server than the TLS server name (421), unless the
    /// listener allowed it.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let pinned = cx.request().tls().and_then(|t| t.peer_spki_sha256()).is_some();
    ///         cx.text(200, if pinned { "client certificate" } else { "none" })
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "none");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn tls(&self) -> Option<&'r serve_net::net_io::TlsInfo> {
        self.env.tls()
    }

    /// The pattern of the matched route (`/users/:id`), once routing ran.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/users/:id", |cx| cx.text(200, cx.request().route().unwrap_or(""))))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /users/7 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "/users/:id");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn route(&self) -> Option<&'r str> {
        self.route
    }

    /// The request's reference.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let same = cx.request().id() == cx.id();
    ///         cx.text(200, if same { "same" } else { "different" })
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "same");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn id(&self) -> RequestId {
        RequestId::of(self.env)
    }

    /// serve-net's facts about the request.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let seq = cx.request().envelope().seq().get().to_string();
    ///         cx.text(200, &seq)
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "1");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn envelope(&self) -> &'r Envelope {
        self.env
    }

    /// The raw request: the target as received, every field, the body.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/page", |cx| cx.text(200, cx.request().raw().head().target())))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /page?x=1 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "/page?x=1");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn raw(&self) -> &'r HttpRequest<'r> {
        self.http
    }
}

impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method())
            .field("path", &self.path)
            .field("route", &self.route)
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}
