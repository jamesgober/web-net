//! # web_net
//!
//! The web layer on serve-net: what a site is written in.
//!
//! A site in five lines:
//!
//! ```no_run
//! use web_net::{App, get};
//!
//! App::builder()
//!     .route(get("/", |cx| cx.html(200, "<h1>Hello</h1>")))
//!     .route(get("/posts/:slug", |cx| cx.text(200, &cx.param("slug")?)))
//!     .build()?
//!     .listen("127.0.0.1:8080")?
//!     .wait();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! A handler gets a [`Cx`] and ends with one reply: [`Cx::html`],
//! [`Cx::text`], [`Cx::bytes`], [`Cx::redirect`], or [`Cx::render`] for a
//! template. `?` turns any error into the right error page.
//!
//! A request runs one fixed path, and each step either answers or hands on:
//!
//! 1. **site**: the `Host` picks the site (unknown hosts get 421, aliases a
//!    redirect to the canonical host), and its base path is removed, so a
//!    site works installed in a folder.
//! 2. **url**: the path is decoded once, dot segments are removed, empty
//!    segments collapse, and the trailing-slash policy applies. A path that
//!    was not spelled canonically is redirected to the spelling that is, so
//!    two spellings never reach different routes. An encoded slash, an
//!    encoded backslash, a control character, or bytes that are not UTF-8
//!    are refused with 400.
//! 3. **authenticate**: the [`Gate`] says who is asking (or a front that
//!    authenticated already passes the identity to [`App::respond`]).
//! 4. **route**: a trie compiled at build time matches the path (404 when
//!    nothing does).
//! 5. **method**: `HEAD` follows `GET`, `OPTIONS` is answered for every
//!    route, anything else the route does not take is a 405 with `Allow`.
//! 6. **authorize**: the route's rule, checked by the gate. With a gate that
//!    has rules, every route declares its access,
//!    [`public`](Route::public) or [`allow`](Route::allow), and a route
//!    without one stops the build. With [`Open`] (no sign-in) every route is
//!    public.
//! 7. **hooks and handler**: registered [`Hook`]s for this route, then the
//!    handler, which receives a [`Cx`]: proof the request passed its gate.
//! 8. **render**: a [`Render`] engine writes the page from a typed [`View`],
//!    no JSON in between.
//! 9. **errors**: every refusal and error is answered by one function, with
//!    the site's error template or a built-in page, and reported through
//!    [`Events`].
//!
//! ```
//! use web_net::{App, get};
//!
//! let app = App::builder()
//!     .host("example.com")
//!     .alias("www.example.com")
//!     .base("/blog")
//!     .route(get("/", |cx| cx.html(200, "<h1>Blog</h1>")))
//!     .route(get("/posts/:slug", |cx| cx.text(200, &cx.param("slug")?)))
//!     .build()?;
//!
//! use serve_net::testing::respond;
//! let r = respond(&app, b"GET /blog/posts/hello HTTP/1.1\r\nHost: example.com\r\n\r\n");
//! assert_eq!((r.status, r.text()), (200, "hello"));
//!
//! let r = respond(&app, b"GET /blog/./posts//hello/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
//! assert_eq!((r.status, r.header("location")), (301, Some(&b"/blog/posts/hello"[..])));
//!
//! let r = respond(&app, b"GET /blog HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
//! assert_eq!(r.header("location"), Some(&b"http://example.com/blog/"[..]));
//!
//! let r = respond(&app, b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n");
//! assert_eq!(r.status, 421);
//! # Ok::<(), web_net::BuildError>(())
//! ```
//!
//! [`App::listen`] serves one app on one address with serve-net's defaults.
//! For TLS, several listeners, or other limits, an [`App`] is a
//! `serve_net::HttpService`: `serve_net::Server::builder()...serve(app)`.
//!
//! The reference with every public item is `docs/API.md` in the
//! repository.

#![doc(html_root_url = "https://docs.rs/web-net")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod app;
mod assets;
mod cors;
mod csrf;
mod cx;
mod error;
mod events;
mod gate;
mod headers;
mod policy;
mod render;
mod request;
mod route;
mod router;
mod sites;
mod url;

pub use app::{App, Builder, Classified, DEFAULT_PAGE_LIMIT, Hook, RouteId, Routes};
pub use assets::{Assets, INLINE_LIMIT, mime_for};
pub use cors::Cors;
pub use cx::Cx;
pub use error::{BuildError, Error, Problem, Result};
pub use events::{Checkpoint, Event, EventKind, Events, NoEvents, Stage};
pub use gate::{Denial, DenialKind, Gate, Guest, Identity, NoRule, Open};
pub use headers::{DEFAULT_CSP, SecurityHeaders};
pub use policy::{CachePolicy, Cacheable, Compression, Served};
pub use render::{
    ErrorPage, Fields, Key, List, NoRender, Output, Render, RenderError, SafeHtml, Shape, ShapeId,
    TemplateId, Value, View,
};
pub use request::{Ambiguous, Request, RequestId};
pub use route::{Group, Handler, Route, delete, get, patch, post, put};
pub use router::MAX_PARAMS;
pub use sites::Sites;
pub use url::{TrailingSlash, UrlError};

/// cookie-net, at the version web-net uses, for [`Cx::set_cookie`].
pub use cookie_net;
/// csrf-sec, at the version web-net uses, for [`Builder::csrf`].
pub use csrf_sec;
/// form-net, at the version web-net uses, for [`Cx::form`] and its `form!`
/// macro.
pub use form_net;

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The README and `docs/API.md` are compiled and run as doctests, so the
/// reference cannot drift from the API.
#[cfg(all(doctest, feature = "uploads"))]
mod doc_tests {
    #[doc = include_str!("../README.md")]
    struct Readme;
    #[doc = include_str!("../docs/API.md")]
    struct ApiReference;
}

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
