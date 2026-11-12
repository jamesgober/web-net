//! Cross-origin resource sharing, declared per route or group.
//!
//! A route without a [`Cors`] policy answers no cross-origin request with
//! CORS fields, so a browser keeps another origin's script from reading it.
//! With one, a preflight (`OPTIONS` with `Access-Control-Request-Method`) is
//! answered before the gate (preflights carry no credentials), and replies to
//! allowed origins carry `Access-Control-Allow-Origin`.
//!
//! CORS relaxes what a browser lets a page read; it is not authentication.
//! A cross-origin `POST` still meets the CSRF step: an origin allowed here
//! for unsafe methods must also be allowed in the `Csrf` builder
//! (`allow_origin`), or the route must take its token from a header.

use std::fmt::Write as _;

use serve_net::http_net::MethodSet;
use serve_net::{HttpReply, Method};

/// A CORS policy.
///
/// ```
/// use web_net::Cors;
///
/// let api = Cors::new()
///     .origin("https://app.example.com")
///     .headers(&["content-type", "x-csrf-token"])
///     .credentials()
///     .max_age(600);
/// # let _ = api;
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cors {
    pub(crate) origins: Vec<Box<str>>,
    pub(crate) any: bool,
    pub(crate) headers: Vec<Box<str>>,
    pub(crate) expose: Vec<Box<str>>,
    pub(crate) credentials: bool,
    pub(crate) max_age: u32,
}

impl Cors {
    /// A policy that allows no origin yet.
    ///
    /// ```
    /// use web_net::{App, Cors, get};
    ///
    /// // A policy that allows no origin is refused at build.
    /// let empty = App::builder().route(get("/api", |cx| cx.text(200, "[]")).cors(Cors::new())).build();
    /// assert!(empty.is_err());
    ///
    /// let app = App::builder()
    ///     .route(get("/api", |cx| cx.text(200, "[]")).cors(Cors::new().origin("https://app.example.com")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\n\r\n");
    /// assert_eq!(r.header("access-control-allow-origin"), Some(&b"https://app.example.com"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_age: 300,
            ..Self::default()
        }
    }

    /// Allows an origin, exactly as browsers send it
    /// (`https://app.example.com`, with a port when it has one).
    ///
    /// ```
    /// use web_net::{App, Cors, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/api", |cx| cx.text(200, "[]")).cors(Cors::new().origin("https://app.example.com")))
    ///     .build()?;
    /// let from = |origin: &str| serve_net::testing::respond(&app, format!("GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: {origin}\r\n\r\n").as_bytes());
    /// assert!(from("https://app.example.com").header("access-control-allow-origin").is_some());
    /// assert!(from("https://other.example").header("access-control-allow-origin").is_none());
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn origin(mut self, origin: &str) -> Self {
        self.origins.push(origin.to_ascii_lowercase().into());
        self
    }

    /// Allows every origin (answered with `*`). Not with
    /// [`credentials`](Self::credentials): the build refuses that pair.
    ///
    /// ```
    /// use web_net::{App, Cors, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/api", |cx| cx.text(200, "[]")).cors(Cors::new().any_origin()))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\n\r\n");
    /// assert_eq!(r.header("access-control-allow-origin"), Some(&b"*"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn any_origin(mut self) -> Self {
        self.any = true;
        self
    }

    /// Request fields a cross-origin request may send beyond the simple ones
    /// (`content-type`, `x-csrf-token`).
    ///
    /// ```
    /// use web_net::{App, Cors, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/api", |cx| cx.text(200, "[]")).cors(Cors::new().origin("https://app.example.com").headers(&["x-csrf-token"])))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nAccess-Control-Request-Method: GET\r\nAccess-Control-Request-Headers: x-csrf-token\r\n\r\n");
    /// assert_eq!(r.header("access-control-allow-headers"), Some(&b"x-csrf-token"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn headers(mut self, names: &[&str]) -> Self {
        self.headers.extend(
            names
                .iter()
                .map(|n| n.to_ascii_lowercase().into_boxed_str()),
        );
        self
    }

    /// Reply fields a cross-origin script may read beyond the simple ones.
    ///
    /// ```
    /// use web_net::{App, Cors, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/api", |cx| cx.text(200, "[]")).cors(Cors::new().origin("https://app.example.com").expose(&["x-total"])))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\n\r\n");
    /// assert_eq!(r.header("access-control-expose-headers"), Some(&b"x-total"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn expose(mut self, names: &[&str]) -> Self {
        self.expose.extend(
            names
                .iter()
                .map(|n| n.to_ascii_lowercase().into_boxed_str()),
        );
        self
    }

    /// Cross-origin requests may carry cookies.
    ///
    /// ```
    /// use web_net::{App, Cors, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/api", |cx| cx.text(200, "[]")).cors(Cors::new().origin("https://app.example.com").credentials()))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\n\r\n");
    /// assert_eq!(r.header("access-control-allow-credentials"), Some(&b"true"[..]));
    ///
    /// // Any origin with credentials is refused at build.
    /// let open = App::builder().route(get("/api", |cx| cx.text(200, "[]")).cors(Cors::new().any_origin().credentials()));
    /// assert!(open.build().is_err());
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn credentials(mut self) -> Self {
        self.credentials = true;
        self
    }

    /// How long a browser may keep a preflight's answer (default 300 s).
    ///
    /// ```
    /// use web_net::{App, Cors, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/api", |cx| cx.text(200, "[]")).cors(Cors::new().origin("https://app.example.com").headers(&["x-csrf-token"]).max_age(600)))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nAccess-Control-Request-Method: GET\r\nAccess-Control-Request-Headers: x-csrf-token\r\n\r\n");
    /// assert_eq!(r.header("access-control-max-age"), Some(&b"600"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn max_age(mut self, seconds: u32) -> Self {
        self.max_age = seconds;
        self
    }

    /// Why the policy cannot be used, if it cannot.
    pub(crate) fn problem(&self) -> Option<&'static str> {
        if self.any && self.credentials {
            return Some("a CORS policy cannot allow any origin and credentials together");
        }
        if !self.any && self.origins.is_empty() {
            return Some("a CORS policy needs at least one origin");
        }
        let token = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        };
        if !self.headers.iter().chain(&self.expose).all(|h| token(h)) {
            return Some("a CORS field name is not a token");
        }
        let origin_ok = |o: &str| {
            (o.starts_with("https://") || o.starts_with("http://"))
                && !o.ends_with('/')
                && o.bytes().all(|b| (0x21..0x7f).contains(&b))
        };
        if !self.origins.iter().all(|o| origin_ok(o)) {
            return Some("a CORS origin must be scheme://host[:port] with no path");
        }
        None
    }

    /// The `Access-Control-Allow-Origin` value for `origin`, if allowed.
    pub(crate) fn allow<'o>(&self, origin: &'o [u8]) -> Option<&'o [u8]> {
        if self.any {
            return Some(b"*");
        }
        let o = core::str::from_utf8(origin).ok()?;
        self.origins
            .iter()
            .any(|a| a.eq_ignore_ascii_case(o))
            .then_some(origin)
    }

    /// The fields on a reply to an allowed origin.
    pub(crate) fn actual(&self, origin: Option<&[u8]>, reply: &mut HttpReply) {
        reply.header("vary", "origin");
        let Some(allowed) = origin.and_then(|o| self.allow(o)) else {
            return;
        };
        reply.header("access-control-allow-origin", allowed);
        if self.credentials {
            reply.header("access-control-allow-credentials", "true");
        }
        if !self.expose.is_empty() {
            reply.header("access-control-expose-headers", self.expose.join(", "));
        }
    }

    /// Answers a preflight. `methods` are the path's methods. Returns
    /// whether the preflight was allowed.
    pub(crate) fn preflight(
        &self,
        origin: &[u8],
        method: Method,
        requested_headers: Option<&[u8]>,
        methods: MethodSet,
        reply: &mut HttpReply,
    ) -> bool {
        reply.status(204).header("vary", "origin");
        let Some(allowed) = self.allow(origin) else {
            return false;
        };
        if !methods.contains(method) {
            return false;
        }
        if let Some(req) = requested_headers {
            let Ok(req) = core::str::from_utf8(req) else {
                return false;
            };
            for name in req.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                if !self.headers.iter().any(|h| h.eq_ignore_ascii_case(name)) {
                    return false;
                }
            }
        }
        let mut allow = Vec::new();
        methods.write_allow(&mut allow);
        reply
            .header("access-control-allow-origin", allowed)
            .header("access-control-allow-methods", allow);
        if !self.headers.is_empty() {
            reply.header("access-control-allow-headers", self.headers.join(", "));
        }
        if self.credentials {
            reply.header("access-control-allow-credentials", "true");
        }
        let mut age = String::new();
        let _ = write!(age, "{}", self.max_age);
        reply.header("access-control-max-age", age);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problems() {
        assert!(Cors::new().problem().is_some());
        assert!(Cors::new().any_origin().credentials().problem().is_some());
        assert!(Cors::new().origin("https://a.example/").problem().is_some());
        assert!(Cors::new().origin("a.example").problem().is_some());
        assert!(
            Cors::new()
                .origin("https://a.example")
                .headers(&["bad name"])
                .problem()
                .is_some()
        );
        assert!(
            Cors::new()
                .origin("https://a.example:8443")
                .problem()
                .is_none()
        );
        assert!(Cors::new().any_origin().problem().is_none());
    }

    #[test]
    fn test_allow() {
        let c = Cors::new().origin("https://a.example");
        assert_eq!(
            c.allow(b"https://A.example"),
            Some(&b"https://A.example"[..])
        );
        assert_eq!(c.allow(b"https://b.example"), None);
        assert_eq!(c.allow(b"null"), None);
        assert_eq!(
            Cors::new().any_origin().allow(b"https://x"),
            Some(&b"*"[..])
        );
    }
}
