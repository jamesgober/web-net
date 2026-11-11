//! Per-route cache policy, the cacheability report, and response
//! compression.

use serve_net::Outcome;

use crate::RouteId;

/// How a route's pages may be cached. Applied as `Cache-Control` unless the
/// handler set one itself.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CachePolicy {
    /// No `Cache-Control` from web-net (the default): the handler decides.
    #[default]
    Unset,
    /// `no-store`: never kept (account pages, anything personal).
    NoStore,
    /// `private, max-age=N`: the visitor's browser only.
    Private {
        /// Seconds.
        max_age: u32,
    },
    /// `public, max-age=N` for everyone.
    Public {
        /// Seconds.
        max_age: u32,
    },
    /// `public, max-age=N` for guests, `private, no-store` for signed-in
    /// visitors: the same page, cached only while it is the same for
    /// everyone. A cache in front of web-net may keep guests' copies
    /// ([`Served::cache`]).
    Guests {
        /// Seconds.
        max_age: u32,
    },
}

impl CachePolicy {
    /// The `Cache-Control` value for a visitor.
    pub(crate) fn value(self, guest: bool) -> Option<String> {
        match self {
            Self::Unset => None,
            Self::NoStore => Some("no-store".into()),
            Self::Private { max_age } => Some(format!("private, max-age={max_age}")),
            Self::Public { max_age } => Some(format!("public, max-age={max_age}")),
            Self::Guests { max_age } if guest => Some(format!("public, max-age={max_age}")),
            Self::Guests { .. } => Some("private, no-store".into()),
        }
    }
}

/// Whether a cache in front of web-net may keep this reply for guests.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Cacheable {
    /// Do not keep it.
    #[default]
    No,
    /// Keep it for guests' `GET` and `HEAD` of the same target, this long.
    /// Said only when the route's policy allows it, the request was a
    /// guest's `GET` or `HEAD`, the status is 200, and the reply sets no
    /// cookie and varies on nothing but `Accept-Encoding`.
    Guests {
        /// Seconds.
        max_age: u32,
    },
}

/// What [`App::respond`](crate::App::respond) reports with the outcome.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Served {
    /// serve-net's outcome.
    pub outcome: Outcome,
    /// The route that ran, if one did.
    pub route: Option<RouteId>,
    /// Whether a cache in front may keep the reply.
    pub cache: Cacheable,
}

/// Response compression with gzip (compress-lib), for deployments where
/// nothing in front compresses.
///
/// Compression together with secrets and reflected input in one page can
/// leak the secrets (BREACH). csrf-sec masks its tokens per response, which
/// is the defence for them; other secrets in compressed pages are the
/// application's to consider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compression {
    pub(crate) min_bytes: usize,
    pub(crate) level: u8,
}

impl Default for Compression {
    fn default() -> Self {
        Self {
            min_bytes: 1024,
            level: 6,
        }
    }
}

impl Compression {
    /// Bodies smaller than this are sent as they are (default 1024).
    #[must_use]
    pub fn min_bytes(mut self, bytes: usize) -> Self {
        self.min_bytes = bytes;
        self
    }

    /// The level, 1 (fastest) to 9 (smallest); default 6.
    #[must_use]
    pub fn level(mut self, level: u8) -> Self {
        self.level = level.clamp(1, 9);
        self
    }
}

/// Media types worth compressing.
pub(crate) fn compressible(content_type: &[u8]) -> bool {
    let t = content_type.split(|&b| b == b';').next().unwrap_or(b"");
    let t = t.trim_ascii();
    t.starts_with(b"text/")
        || matches!(
            t,
            b"application/json"
                | b"application/javascript"
                | b"application/xml"
                | b"application/manifest+json"
                | b"application/rss+xml"
                | b"application/atom+xml"
                | b"image/svg+xml"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_values() {
        assert_eq!(CachePolicy::Unset.value(true), None);
        assert_eq!(
            CachePolicy::Guests { max_age: 60 }.value(true).unwrap(),
            "public, max-age=60"
        );
        assert_eq!(
            CachePolicy::Guests { max_age: 60 }.value(false).unwrap(),
            "private, no-store"
        );
        assert_eq!(
            CachePolicy::Private { max_age: 5 }.value(false).unwrap(),
            "private, max-age=5"
        );
    }

    #[test]
    fn test_compressible() {
        assert!(compressible(b"text/html; charset=utf-8"));
        assert!(compressible(b"application/json"));
        assert!(!compressible(b"image/png"));
        assert!(!compressible(b""));
    }
}
