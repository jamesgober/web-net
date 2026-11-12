//! The two gate checkpoints: authentication (who is asking) and
//! authorization (may they use this route).
//!
//! A handler only ever receives a [`Context`](crate::Context), and web-net builds one
//! only after the route's access check passed. There is no other way to
//! make one, so a route that skips the gate does not compile.

use std::fmt;

use crate::Request;

/// Who is asking. A request that reaches a handler always carries one,
/// possibly a guest.
///
/// ```
/// use web_net::Identity;
///
/// struct User { session: Option<Vec<u8>> }
/// impl Identity for User {
///     fn is_guest(&self) -> bool { self.session.is_none() }
///     fn csrf_binding(&self) -> Option<&[u8]> { self.session.as_deref() }
/// }
///
/// let ann = User { session: Some(b"s-41".to_vec()) };
/// assert!(!ann.is_guest());
/// assert_eq!(ann.csrf_binding(), Some(&b"s-41"[..]));
/// assert_eq!(ann.set_cookie(), None); // the default
/// ```
pub trait Identity: Send + Sync + 'static {
    /// Whether this is a visitor with no signed-in session.
    fn is_guest(&self) -> bool;

    /// The value CSRF tokens are bound to: the session id, or a pre-session
    /// id for a guest. `None` means no binding exists, and an unsafe method
    /// on a CSRF-protected route is refused.
    fn csrf_binding(&self) -> Option<&[u8]> {
        None
    }

    /// A `Set-Cookie` value the gate wants on the reply (a dead session's
    /// cookie cleared, a pre-session id set). [`App::respond`](crate::App::respond)
    /// writes it on every exit after authentication, once; when the caller
    /// passes an identity to `respond`, it authenticated and writes its own. A reply that carries it is never
    /// reported as keepable by a cache.
    fn set_cookie(&self) -> Option<&str> {
        None
    }
}

/// The identity of [`Open`]: everyone is a guest.
///
/// ```
/// use web_net::{Guest, Identity};
///
/// assert!(Guest.is_guest());
/// assert_eq!(Guest.csrf_binding(), None);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Guest;

impl Identity for Guest {
    #[inline]
    fn is_guest(&self) -> bool {
        true
    }
}

/// Authentication and authorization, the two checkpoints a request passes
/// before a handler runs.
///
/// One trait, so an application has one type parameter. An implementation
/// backed by remote state fails closed: when it cannot decide, it denies.
///
/// ```
/// use web_net::{Denial, Gate, Identity, Request};
///
/// struct User { admin: bool }
/// impl Identity for User {
///     fn is_guest(&self) -> bool { false }
/// }
///
/// enum Rule { Admin }
///
/// struct Demo;
/// impl Gate for Demo {
///     type Identity = User;
///     type Rule = Rule;
///     fn authenticate(&self, req: &Request<'_>) -> Result<User, Denial> {
///         Ok(User { admin: req.header("x-demo-admin").is_some() })
///     }
///     fn authorize(&self, who: &User, rule: &Rule, _req: &Request<'_>) -> Result<(), Denial> {
///         match rule {
///             Rule::Admin if who.admin => Ok(()),
///             Rule::Admin => Err(Denial::forbidden("demo.not_admin")),
///         }
///     }
/// }
/// ```
pub trait Gate: Send + Sync + 'static {
    /// Who a request comes from.
    type Identity: Identity;

    /// A route's access rule, declared with [`Route::allow`](crate::Route::allow).
    type Rule: Send + Sync + 'static;

    /// Runs once per request, before routing. A missing or invalid
    /// credential is a guest (`Ok`); a banned visitor is a denial.
    ///
    /// Not called when the caller passes an identity to
    /// [`App::respond`](crate::App::respond): it authenticated already.
    ///
    /// # Errors
    ///
    /// A [`Denial`] ends the request with its status.
    fn authenticate(&self, req: &Request<'_>) -> Result<Self::Identity, Denial>;

    /// Runs after the route and method matched and before anything else of
    /// the route. Not called for routes declared public.
    ///
    /// # Errors
    ///
    /// A [`Denial`] ends the request with its status.
    fn authorize(
        &self,
        who: &Self::Identity,
        rule: &Self::Rule,
        req: &Request<'_>,
    ) -> Result<(), Denial>;
}

/// A rule that cannot be made: the rule type of [`Open`], whose routes can
/// only be public.
///
/// ```
/// use web_net::{Gate, NoRule, Open};
///
/// // No value of `NoRule` exists, so no route of an `Open` app can carry a rule.
/// fn rule_type<G: Gate<Rule = NoRule>>(_: &G) {}
/// rule_type(&Open);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoRule {}

/// The default gate: every visitor is a [`Guest`], and only routes declared
/// [`public`](crate::Route::public) can exist.
///
/// ```
/// use web_net::{App, Open, get};
///
/// let app = App::with_gate(Open).route(get("/", |cx| cx.text(200, "hi"))).build()?;
/// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.text(), "hi");
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Open;

impl Gate for Open {
    type Identity = Guest;
    type Rule = NoRule;

    #[inline]
    fn authenticate(&self, _req: &Request<'_>) -> Result<Guest, Denial> {
        Ok(Guest)
    }

    fn authorize(&self, _who: &Guest, rule: &NoRule, _req: &Request<'_>) -> Result<(), Denial> {
        match *rule {}
    }
}

/// What the visitor is told when a gate denies.
///
/// ```
/// use web_net::{Denial, DenialKind};
///
/// assert_eq!(Denial::hidden("post.draft").kind(), DenialKind::Hidden);
/// assert_eq!(Denial::with_status(429, "rate.limited").kind(), DenialKind::Status(429));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenialKind {
    /// Sign in first: a 303 to the site's sign-in page for a page request,
    /// a 401 otherwise.
    SignIn,
    /// 403 Forbidden.
    Forbidden,
    /// 404 Not Found: the visitor is not told that the thing exists.
    Hidden,
    /// Another 4xx status (a 429 for a standing limit, for example).
    Status(u16),
    /// 503 Service Unavailable: the gate cannot decide now (its stores are
    /// down) and fails closed; the client may retry.
    Unavailable,
}

/// A refusal from a gate: what the visitor sees, and a stable code for logs
/// and events (never shown to the visitor).
///
/// ```
/// use web_net::Denial;
///
/// let d = Denial::forbidden("admin.only");
/// assert_eq!((d.status(), d.code()), (403, "admin.only"));
/// assert_eq!(d.to_string(), "denied (403): admin.only");
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Denial {
    kind: DenialKind,
    code: &'static str,
    cookie: Option<Box<str>>,
    retry_after: Option<u32>,
}

impl Denial {
    /// Sign in first.
    ///
    /// ```
    /// use web_net::{Denial, DenialKind};
    ///
    /// let d = Denial::sign_in("session.none");
    /// assert_eq!((d.kind(), d.status()), (DenialKind::SignIn, 401));
    /// ```
    #[must_use]
    pub const fn sign_in(code: &'static str) -> Self {
        Self {
            kind: DenialKind::SignIn,
            code,
            cookie: None,
            retry_after: None,
        }
    }

    /// 403 Forbidden.
    ///
    /// ```
    /// use web_net::Denial;
    ///
    /// assert_eq!(Denial::forbidden("account.locked").status(), 403);
    /// ```
    #[must_use]
    pub const fn forbidden(code: &'static str) -> Self {
        Self {
            kind: DenialKind::Forbidden,
            code,
            cookie: None,
            retry_after: None,
        }
    }

    /// 404 Not Found, hiding that the resource exists.
    ///
    /// ```
    /// use web_net::Denial;
    ///
    /// assert_eq!(Denial::hidden("post.draft").status(), 404);
    /// ```
    #[must_use]
    pub const fn hidden(code: &'static str) -> Self {
        Self {
            kind: DenialKind::Hidden,
            code,
            cookie: None,
            retry_after: None,
        }
    }

    /// Another client-error status (429, 451, ...). A status outside 400
    /// to 499 is answered as 403: a gate cannot turn a denial into a success
    /// or a server error.
    ///
    /// ```
    /// use web_net::Denial;
    ///
    /// assert_eq!(Denial::with_status(429, "rate.limited").status(), 429);
    /// assert_eq!(Denial::with_status(500, "oops").status(), 403);
    /// ```
    #[must_use]
    pub const fn with_status(status: u16, code: &'static str) -> Self {
        let kind = if matches!(status, 400..=499) {
            DenialKind::Status(status)
        } else {
            DenialKind::Forbidden
        };
        Self {
            kind,
            code,
            cookie: None,
            retry_after: None,
        }
    }

    /// 503 Service Unavailable: the gate cannot decide now (a store it
    /// needs is down) and fails closed. Clients and load balancers read it
    /// as "try again", not "you may not".
    ///
    /// ```
    /// use web_net::Denial;
    ///
    /// let d = Denial::unavailable("gate.unavailable").retry_after(5);
    /// assert_eq!((d.status(), d.retry_seconds()), (503, Some(5)));
    /// ```
    #[must_use]
    pub const fn unavailable(code: &'static str) -> Self {
        Self {
            kind: DenialKind::Unavailable,
            code,
            cookie: None,
            retry_after: None,
        }
    }

    /// A `Retry-After: <seconds>` field on the refusal. Sent only when the
    /// status is 429 or 503, the statuses a client retries.
    ///
    /// ```
    /// use web_net::Denial;
    ///
    /// let d = Denial::with_status(429, "rate.limited").retry_after(30);
    /// assert_eq!(d.retry_seconds(), Some(30));
    /// ```
    #[must_use]
    pub const fn retry_after(mut self, seconds: u32) -> Self {
        self.retry_after = Some(seconds);
        self
    }

    /// The `Retry-After` seconds, if any.
    ///
    /// ```
    /// use web_net::Denial;
    ///
    /// assert_eq!(Denial::forbidden("account.locked").retry_seconds(), None);
    /// assert_eq!(Denial::unavailable("store.down").retry_after(5).retry_seconds(), Some(5));
    /// ```
    #[must_use]
    pub const fn retry_seconds(&self) -> Option<u32> {
        self.retry_after
    }

    /// A `Set-Cookie` value the refusal carries (a dead session's cookie
    /// cleared): written on the denial's reply.
    ///
    /// ```
    /// use web_net::Denial;
    ///
    /// let d = Denial::sign_in("session.expired").with_cookie("sid=; Max-Age=0; Path=/");
    /// assert_eq!(d.cookie(), Some("sid=; Max-Age=0; Path=/"));
    /// ```
    #[must_use]
    pub fn with_cookie(mut self, set_cookie: impl Into<Box<str>>) -> Self {
        self.cookie = Some(set_cookie.into());
        self
    }

    /// The `Set-Cookie` value, if any.
    ///
    /// ```
    /// use web_net::Denial;
    ///
    /// assert_eq!(Denial::forbidden("account.locked").cookie(), None);
    /// assert!(Denial::sign_in("session.expired").with_cookie("sid=; Max-Age=0").cookie().is_some());
    /// ```
    #[must_use]
    pub fn cookie(&self) -> Option<&str> {
        self.cookie.as_deref()
    }

    /// What the visitor is told.
    ///
    /// ```
    /// use web_net::{Denial, DenialKind};
    ///
    /// assert_eq!(Denial::unavailable("store.down").kind(), DenialKind::Unavailable);
    /// ```
    #[must_use]
    pub const fn kind(&self) -> DenialKind {
        self.kind
    }

    /// The code for logs and events.
    ///
    /// ```
    /// use web_net::Denial;
    ///
    /// assert_eq!(Denial::hidden("post.draft").code(), "post.draft");
    /// ```
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The status answered when no sign-in page applies.
    ///
    /// ```
    /// use web_net::Denial;
    ///
    /// assert_eq!(Denial::sign_in("session.none").status(), 401);
    /// assert_eq!(Denial::unavailable("store.down").status(), 503);
    /// ```
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self.kind {
            DenialKind::SignIn => 401,
            DenialKind::Forbidden => 403,
            DenialKind::Hidden => 404,
            DenialKind::Status(s) => s,
            DenialKind::Unavailable => 503,
        }
    }
}

impl fmt::Debug for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Denial")
            .field("kind", &self.kind)
            .field("code", &self.code)
            .field("cookie", &self.cookie.as_ref().map(|_| "<set>"))
            .field("retry_after", &self.retry_after)
            .finish()
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "denied ({}): {}", self.status(), self.code)
    }
}

impl std::error::Error for Denial {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_denial_statuses() {
        assert_eq!(Denial::sign_in("a").status(), 401);
        assert_eq!(Denial::forbidden("a").status(), 403);
        assert_eq!(Denial::hidden("a").status(), 404);
        assert_eq!(Denial::with_status(429, "a").status(), 429);
        assert_eq!(Denial::with_status(200, "a").status(), 403);
        assert_eq!(Denial::with_status(500, "a").status(), 403);
        assert_eq!(Denial::forbidden("x.y").code(), "x.y");
        assert_eq!(Denial::unavailable("a").status(), 503);
        assert_eq!(Denial::unavailable("a").kind(), DenialKind::Unavailable);
        assert_eq!(Denial::unavailable("a").retry_seconds(), None);
        assert_eq!(
            Denial::forbidden("a").retry_after(3).retry_seconds(),
            Some(3)
        );
    }
}
