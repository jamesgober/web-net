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
pub trait Events: Send + Sync + 'static {
    /// One event.
    fn event(&self, event: &Event<'_>) {
        let _ = event;
    }
}

/// Reports nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoEvents;

impl Events for NoEvents {}

/// A point in web-net's pipeline where a checkpoint runs.
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
pub trait Checkpoint: Send + Sync + 'static {
    /// Decides at one stage.
    fn check(&self, env: &Envelope, at: Stage) -> Verdict;
}
