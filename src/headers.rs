//! The security headers every reply carries, from one policy.

/// The security headers added to every reply web-net sends (pages, error
/// pages, files, redirects), unless the handler set the same field itself.
///
/// The defaults are strict: a page may load scripts, styles, images, and
/// fonts from its own origin only, may not be framed, and sends a short
/// referrer to other origins. A site that needs more says so.
///
/// ```
/// use web_net::SecurityHeaders;
///
/// let policy = SecurityHeaders::default()
///     .content_security_policy("default-src 'self'; img-src 'self' https://cdn.example; frame-ancestors 'none'")
///     .hsts(63_072_000, true);
/// # let _ = policy;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityHeaders {
    pub(crate) csp: Option<Box<str>>,
    pub(crate) frame: Option<Box<str>>,
    pub(crate) referrer: Option<Box<str>>,
    pub(crate) permissions: Option<Box<str>>,
    pub(crate) coop: Option<Box<str>>,
    pub(crate) hsts: Option<Box<str>>,
}

/// The default content security policy.
///
/// ```
/// use web_net::{App, DEFAULT_CSP, get};
///
/// let app = App::builder().route(get("/", |cx| cx.text(200, "ok"))).build()?;
/// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.header("content-security-policy"), Some(DEFAULT_CSP.as_bytes()));
/// # Ok::<(), web_net::BuildError>(())
/// ```
pub const DEFAULT_CSP: &str = "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            csp: Some(DEFAULT_CSP.into()),
            frame: Some("DENY".into()),
            referrer: Some("strict-origin-when-cross-origin".into()),
            permissions: Some("camera=(), microphone=(), geolocation=(), payment=()".into()),
            coop: Some("same-origin".into()),
            hsts: Some("max-age=31536000".into()),
        }
    }
}

impl SecurityHeaders {
    /// No security headers at all (`x-content-type-options: nosniff` is
    /// still sent: it has no cost and no downside).
    ///
    /// ```
    /// use web_net::{App, SecurityHeaders, get};
    ///
    /// let app = App::builder()
    ///     .security_headers(SecurityHeaders::none())
    ///     .route(get("/", |cx| cx.text(200, "ok")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert!(r.header("content-security-policy").is_none());
    /// assert_eq!(r.header("x-content-type-options"), Some(&b"nosniff"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn none() -> Self {
        Self {
            csp: None,
            frame: None,
            referrer: None,
            permissions: None,
            coop: None,
            hsts: None,
        }
    }

    /// `Content-Security-Policy`.
    ///
    /// ```
    /// use web_net::{App, SecurityHeaders, get};
    ///
    /// let app = App::builder()
    ///     .security_headers(SecurityHeaders::default().content_security_policy("default-src 'self'"))
    ///     .route(get("/", |cx| cx.text(200, "ok")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("content-security-policy"), Some(&b"default-src 'self'"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn content_security_policy(mut self, value: &str) -> Self {
        self.csp = Some(value.into());
        self
    }

    /// No `Content-Security-Policy`.
    ///
    /// ```
    /// use web_net::{App, SecurityHeaders, get};
    ///
    /// let app = App::builder()
    ///     .security_headers(SecurityHeaders::default().no_content_security_policy())
    ///     .route(get("/", |cx| cx.text(200, "ok")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("content-security-policy"), None);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn no_content_security_policy(mut self) -> Self {
        self.csp = None;
        self
    }

    /// `X-Frame-Options` (`DENY` by default; `SAMEORIGIN` to allow the site's
    /// own frames).
    ///
    /// ```
    /// use web_net::{App, SecurityHeaders, get};
    ///
    /// let app = App::builder()
    ///     .security_headers(SecurityHeaders::default().frame_options("SAMEORIGIN"))
    ///     .route(get("/", |cx| cx.text(200, "ok")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("x-frame-options"), Some(&b"SAMEORIGIN"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn frame_options(mut self, value: &str) -> Self {
        self.frame = Some(value.into());
        self
    }

    /// `Referrer-Policy`.
    ///
    /// ```
    /// use web_net::{App, SecurityHeaders, get};
    ///
    /// let app = App::builder()
    ///     .security_headers(SecurityHeaders::default().referrer_policy("no-referrer"))
    ///     .route(get("/", |cx| cx.text(200, "ok")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("referrer-policy"), Some(&b"no-referrer"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn referrer_policy(mut self, value: &str) -> Self {
        self.referrer = Some(value.into());
        self
    }

    /// `Permissions-Policy`.
    ///
    /// ```
    /// use web_net::{App, SecurityHeaders, get};
    ///
    /// let app = App::builder()
    ///     .security_headers(SecurityHeaders::default().permissions_policy("camera=(self)"))
    ///     .route(get("/", |cx| cx.text(200, "ok")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("permissions-policy"), Some(&b"camera=(self)"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn permissions_policy(mut self, value: &str) -> Self {
        self.permissions = Some(value.into());
        self
    }

    /// `Cross-Origin-Opener-Policy`.
    ///
    /// ```
    /// use web_net::{App, SecurityHeaders, get};
    ///
    /// let app = App::builder()
    ///     .security_headers(SecurityHeaders::default().opener_policy("same-origin-allow-popups"))
    ///     .route(get("/", |cx| cx.text(200, "ok")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("cross-origin-opener-policy"), Some(&b"same-origin-allow-popups"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn opener_policy(mut self, value: &str) -> Self {
        self.coop = Some(value.into());
        self
    }

    /// `Strict-Transport-Security`, sent on HTTPS replies only and never to
    /// a development host. `include_subdomains` commits every subdomain to
    /// HTTPS too: set it only when they all have it.
    ///
    /// ```
    /// use web_net::{App, SecurityHeaders, get};
    ///
    /// let app = App::builder()
    ///     .host("example.com")
    ///     .security_headers(SecurityHeaders::default().hsts(63_072_000, true))
    ///     .route(get("/", |cx| cx.text(200, "ok")))
    ///     .build()?;
    /// let r = serve_net::testing::TestRequest::new(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    ///     .scheme(serve_net::Scheme::Https)
    ///     .send(&app);
    /// assert_eq!(r.header("strict-transport-security"), Some(&b"max-age=63072000; includeSubDomains"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn hsts(mut self, max_age: u64, include_subdomains: bool) -> Self {
        let mut v = format!("max-age={max_age}");
        if include_subdomains {
            v.push_str("; includeSubDomains");
        }
        self.hsts = Some(v.into());
        self
    }

    /// No `Strict-Transport-Security`.
    ///
    /// ```
    /// use web_net::{App, SecurityHeaders, get};
    ///
    /// let app = App::builder()
    ///     .host("example.com")
    ///     .security_headers(SecurityHeaders::default().no_hsts())
    ///     .route(get("/", |cx| cx.text(200, "ok")))
    ///     .build()?;
    /// let r = serve_net::testing::TestRequest::new(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    ///     .scheme(serve_net::Scheme::Https)
    ///     .send(&app);
    /// assert_eq!(r.header("strict-transport-security"), None);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn no_hsts(mut self) -> Self {
        self.hsts = None;
        self
    }

    /// The fields to send, in order, for a reply over HTTPS or not.
    pub(crate) fn fields(&self, https: bool) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("content-security-policy", self.csp.as_deref()),
            ("x-frame-options", self.frame.as_deref()),
            ("referrer-policy", self.referrer.as_deref()),
            ("permissions-policy", self.permissions.as_deref()),
            ("cross-origin-opener-policy", self.coop.as_deref()),
            (
                "strict-transport-security",
                self.hsts.as_deref().filter(|_| https),
            ),
        ]
        .into_iter()
        .filter_map(|(n, v)| v.map(|v| (n, v)))
    }

    /// Whether every value is visible ASCII (checked at build).
    pub(crate) fn valid(&self) -> bool {
        self.fields(true)
            .all(|(_, v)| !v.is_empty() && v.bytes().all(|b| (0x20..0x7f).contains(&b)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsts_only_on_https() {
        let p = SecurityHeaders::default();
        assert!(
            p.fields(false)
                .all(|(n, _)| n != "strict-transport-security")
        );
        assert!(
            p.fields(true)
                .any(|(n, _)| n == "strict-transport-security")
        );
        assert_eq!(SecurityHeaders::none().fields(true).count(), 0);
        assert!(p.valid());
        assert!(!SecurityHeaders::default().referrer_policy("a\nb").valid());
    }
}
