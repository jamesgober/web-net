//! What web-net tells the rest of the system, and where it asks whether a
//! request may continue.
//!
//! A security component that cannot report what it sees is a detour, not a
//! defence. Every refusal, denial, and failure is reported through
//! [`Events`], so a detection or gate layer hears about a probe the moment
//! web-net turns it away. Events carry ids, codes, and statuses, never
//! request bytes.

use serve_net::{Envelope, Verdict};

use crate::RequestId;

/// What kind of thing happened.
///
/// ```
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicU32, Ordering};
/// use web_net::{App, Event, EventKind, Events, get};
///
/// #[derive(Default)]
/// struct Refusals(AtomicU32);
/// impl Events for Refusals {
///     fn event(&self, e: &Event<'_>) {
///         if e.kind == EventKind::Refused {
///             self.0.fetch_add(1, Ordering::Relaxed);
///         }
///     }
/// }
///
/// let refusals = Arc::new(Refusals::default());
/// let app = App::builder().events(Arc::clone(&refusals)).build()?;
/// serve_net::testing::respond(&app, b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(refusals.0.load(Ordering::Relaxed), 1);
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// Refused before a handler: a malformed path, an unknown host, no
    /// route, a method the route does not take.
    Refused,
    /// A gate denied the request.
    Denied,
    /// A handler or render failed (any handler error, and every 5xx).
    Failed,
    /// A handler panicked; answered with 500.
    Panicked,
    /// A checkpoint stopped the request in flight.
    Revoked,
}

/// One event.
///
/// ```
/// use std::sync::{Arc, Mutex};
/// use web_net::{App, Event, Events, get};
///
/// #[derive(Default)]
/// struct Codes(Mutex<Vec<(u16, &'static str)>>);
/// impl Events for Codes {
///     fn event(&self, e: &Event<'_>) {
///         self.0.lock().unwrap().push((e.status, e.code));
///     }
/// }
///
/// let codes = Arc::new(Codes::default());
/// let app = App::builder().events(Arc::clone(&codes)).route(get("/", |cx| cx.text(200, "hi"))).build()?;
/// serve_net::testing::respond(&app, b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(*codes.0.lock().unwrap(), [(404, "route.none")]);
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub struct Event<'a> {
    /// What happened.
    pub kind: EventKind,
    /// The request's reference.
    pub id: RequestId,
    /// The matched route's pattern, if routing got that far.
    pub route: Option<&'a str>,
    /// The status answered.
    pub status: u16,
    /// A stable code (`"url.encoded_slash"`, a gate's code, a handler's).
    pub code: &'static str,
    /// The underlying error, for the logs only.
    pub source: Option<&'a (dyn std::error::Error + 'static)>,
}

/// Where web-net reports. Every method has an empty default; the default
/// implementation, [`NoEvents`], reports nothing.
///
/// Called on the request path: keep it to a counter or a queue push.
///
/// ```
/// use std::sync::atomic::{AtomicU32, Ordering};
/// use web_net::{Event, Events};
///
/// // Counts every event; the app reports refusals, denials, and failures here.
/// #[derive(Default)]
/// struct Counter(AtomicU32);
/// impl Events for Counter {
///     fn event(&self, _: &Event<'_>) {
///         self.0.fetch_add(1, Ordering::Relaxed);
///     }
/// }
///
/// let app = web_net::App::builder().events(Counter::default()).build()?;
/// # let _ = app;
/// # Ok::<(), web_net::BuildError>(())
/// ```
pub trait Events: Send + Sync + 'static {
    /// One event.
    fn event(&self, event: &Event<'_>) {
        let _ = event;
    }
}

/// Reports nothing.
///
/// ```
/// use web_net::{App, NoEvents};
///
/// // The default; setting it again turns reporting off.
/// let app = App::builder().events(NoEvents).build()?;
/// # let _ = app;
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct NoEvents;

impl Events for NoEvents {}

/// A sink the application keeps a handle to, to read what it counted.
///
/// ```
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicU32, Ordering};
/// use web_net::{App, Event, Events, get};
///
/// #[derive(Default)]
/// struct Refusals(AtomicU32);
/// impl Events for Refusals {
///     fn event(&self, _: &Event<'_>) {
///         self.0.fetch_add(1, Ordering::Relaxed);
///     }
/// }
///
/// let seen = Arc::new(Refusals::default());
/// let app = App::builder()
///     .events(Arc::clone(&seen))
///     .route(get("/", |cx| cx.text(200, "hi")))
///     .build()?;
/// serve_net::testing::respond(&app, b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(seen.0.load(Ordering::Relaxed), 1);
/// # Ok::<(), web_net::BuildError>(())
/// ```
impl<T: Events + ?Sized> Events for std::sync::Arc<T> {
    fn event(&self, event: &Event<'_>) {
        (**self).event(event);
    }
}

/// A point in web-net's pipeline where a checkpoint runs.
///
/// ```
/// use serve_net::{Envelope, Verdict};
/// use web_net::{App, Checkpoint, Stage, get};
///
/// // Stops requests once their access check passed.
/// struct AfterAccess;
/// impl Checkpoint for AfterAccess {
///     fn check(&self, _: &Envelope, at: Stage) -> Verdict {
///         if at == Stage::Authorized { Verdict::Deny { status: 503 } } else { Verdict::Pass }
///     }
/// }
///
/// let app = App::builder().checkpoint(AfterAccess).route(get("/", |cx| cx.text(200, "hi"))).build()?;
/// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.status, 503);
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// After the route's access check passed, before any hook or handler.
    Authorized,
    /// Before a page is rendered.
    BeforeRender,
}

/// Revocation in flight: a ban, a revoked session, or a lockdown that
/// arrives while a request is being handled. serve-net's own checkpoint
/// covers admission and the moment before the reply leaves; this one covers
/// the points in between that only web-net knows.
///
/// A checkpoint backed by remote state fails closed (denies) when the
/// remote cannot be reached.
///
/// ```
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicBool, Ordering};
/// use serve_net::testing::respond;
/// use serve_net::{Envelope, Verdict};
/// use web_net::{App, Checkpoint, Stage, get};
///
/// #[derive(Default)]
/// struct Lockdown(AtomicBool);
/// impl Checkpoint for Lockdown {
///     fn check(&self, _: &Envelope, _: Stage) -> Verdict {
///         if self.0.load(Ordering::Relaxed) { Verdict::Deny { status: 503 } } else { Verdict::Pass }
///     }
/// }
///
/// let lockdown = Arc::new(Lockdown::default());
/// let app = App::builder().checkpoint(Arc::clone(&lockdown)).route(get("/", |cx| cx.text(200, "hi"))).build()?;
/// let req = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
/// assert_eq!(respond(&app, req).status, 200);
/// lockdown.0.store(true, Ordering::Relaxed);
/// assert_eq!(respond(&app, req).status, 503);
/// # Ok::<(), web_net::BuildError>(())
/// ```
pub trait Checkpoint: Send + Sync + 'static {
    /// Decides at one stage.
    fn check(&self, env: &Envelope, at: Stage) -> Verdict;
}

/// A checkpoint shared with the code that revokes.
impl<T: Checkpoint + ?Sized> Checkpoint for std::sync::Arc<T> {
    fn check(&self, env: &Envelope, at: Stage) -> Verdict {
        (**self).check(env, at)
    }
}
