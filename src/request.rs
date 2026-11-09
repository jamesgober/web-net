//! The request as gates and handlers read it.

use std::fmt;

use serve_net::{ClientInfo, Envelope, HttpRequest, Method, Scheme};

/// A request's reference: the connection id and the request's number on it.
/// Shown on error pages and carried by every event, so a visitor's report
/// finds the log line. Not a security token.
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
    #[must_use]
    pub const fn connection(&self) -> u64 {
        self.connection
    }

    /// The request's number on its connection.
    #[must_use]
    pub const fn seq(&self) -> u32 {
        self.seq
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}-{}", self.connection, self.seq)
    }
}

/// A `Cookie` field held the name more than once, or the request carried
/// more than one `Cookie` field. A gate treats this as no credential, or as
/// an attack; it never picks one of the values.
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
#[derive(Clone, Copy)]
pub struct Request<'r> {
    pub(crate) http: &'r HttpRequest<'r>,
    pub(crate) env: &'r Envelope,
    pub(crate) path: &'r str,
    pub(crate) host: &'r str,
    pub(crate) route: Option<&'r str>,
}

impl<'r> Request<'r> {
    /// The method.
    #[must_use]
    pub fn method(&self) -> Method {
        self.http.method()
    }

    /// The canonical path inside the site: the base path removed, percent
    /// escapes in their one canonical form. `/` for the site root.
    #[must_use]
    pub fn path(&self) -> &'r str {
        self.path
    }

    /// The query after `?`, as received (validated by the parser, not
    /// decoded).
    #[must_use]
    pub fn query(&self) -> Option<&'r str> {
        self.http.query()
    }

    /// The host the request named, as received (empty for an HTTP/1.0
    /// request without one). It matched one of the site's hosts, unless the
    /// site accepts any host.
    #[must_use]
    pub fn host(&self) -> &'r str {
        self.host
    }

    /// The first value of a field.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&'r [u8]> {
        self.http.header(name)
    }

    /// The first value of a field, if it is UTF-8.
    #[must_use]
    pub fn header_str(&self, name: &str) -> Option<&'r str> {
        self.http
            .header(name)
            .and_then(|v| core::str::from_utf8(v).ok())
    }

    /// The value of the cookie `name`, read with cookie-net. `Ok(None)` when
    /// there is no such cookie.
    ///
    /// # Errors
    ///
    /// [`Ambiguous`] when the name appears twice, or the request has more
    /// than one `Cookie` field: a sign of cookie tossing, never resolved by
    /// picking one.
    pub fn cookie(&self, name: &str) -> Result<Option<&'r str>, Ambiguous> {
        let mut fields = self.http.head().header_all("cookie");
        let Some(first) = fields.next() else {
            return Ok(None);
        };
        if fields.next().is_some() {
            return Err(Ambiguous);
        }
        cookie_net::get_unique(first, name).map_err(|_| Ambiguous)
    }

    /// The client, as serve-net established it (the real address behind a
    /// trusted proxy).
    #[must_use]
    pub fn client(&self) -> &'r ClientInfo {
        self.env.client()
    }

    /// `https` when the request came over TLS (or from a trusted proxy that
    /// said so).
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.env.client().scheme()
    }

    /// The pattern of the matched route (`/users/:id`), once routing ran.
    #[must_use]
    pub fn route(&self) -> Option<&'r str> {
        self.route
    }

    /// The request's reference.
    #[must_use]
    pub fn id(&self) -> RequestId {
        RequestId::of(self.env)
    }

    /// serve-net's facts about the request.
    #[must_use]
    pub fn envelope(&self) -> &'r Envelope {
        self.env
    }

    /// The raw request: the target as received, every field, the body.
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
