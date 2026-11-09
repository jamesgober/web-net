//! Request forgery protection on every state-changing request, through
//! csrf-sec.
//!
//! An unsafe method (`POST`, `PUT`, `PATCH`, `DELETE`) on a route that has
//! not opted out passes two checks before any hook or handler runs:
//!
//! 1. **Origin policy**: `Sec-Fetch-Site`, `Origin`, and `Referer`, which an
//!    attacker's page cannot set. A cross-site request is refused here.
//! 2. **A token bound to the visitor's session** (the identity's
//!    [`csrf_binding`](crate::Identity::csrf_binding)): from the
//!    `X-CSRF-Token` field, or from the `csrf_token` form field. A
//!    urlencoded form's token is checked here, before the handler. A
//!    multipart form's token is checked by [`Cx::form`](crate::Cx::form) or
//!    [`Cx::upload`](crate::Cx::upload) in the same pass that reads the body,
//!    before any file byte is stored; until then the raw body cannot be
//!    read, and a handler that returns without reading it has its reply
//!    replaced with 403.
//!
//! Anything else (no binding, no token, another content type without the
//! field) is refused with 403. The visitor sees a generic page; the reason
//! goes to the events.

use csrf_sec::{Csrf, Reason, RequestFacts};
use form_net::{FormKind, Limits, Policy, Refusal, TokenCheck};
use serve_net::HttpRequest;

/// Where a request stands with CSRF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// Nothing to check (a safe method, or a route that opted out).
    Off,
    /// The token was verified.
    Verified,
    /// A multipart body: the token is verified while the form is read.
    Pending,
}

/// The stable code for a csrf-sec refusal.
pub(crate) const fn code(r: Reason) -> &'static str {
    match r {
        Reason::Missing => "csrf.missing",
        Reason::Malformed => "csrf.malformed",
        Reason::UnknownKey => "csrf.unknown_key",
        Reason::BadMac => "csrf.bad_mac",
        Reason::StaleSession => "csrf.stale_session",
        Reason::Expired => "csrf.expired",
        Reason::NotYetValid => "csrf.not_yet_valid",
        Reason::WrongScope => "csrf.wrong_scope",
        Reason::CrossSite => "csrf.cross_site",
        Reason::OriginMismatch => "csrf.origin_mismatch",
        Reason::Unverifiable => "csrf.unverifiable",
        _ => "csrf.rejected",
    }
}

/// The token check form-net runs while it reads a form.
pub(crate) fn token_check<'a>(
    csrf: &'a Csrf,
    binding: &'a [u8],
) -> TokenCheck<impl FnMut(&str) -> Result<(), Refusal> + 'a> {
    TokenCheck::new(csrf_sec::FIELD_NAME, move |token| {
        csrf.verify(binding, token)
            .map(|_| ())
            .map_err(|r| Refusal::new(403, code(r.reason())))
    })
}

/// The form policy when the token comes in the body: it must come before
/// any file part.
pub(crate) const TOKEN_POLICY: Policy =
    Policy::DEFAULT.with_token_field(form_net::TokenField::new(csrf_sec::FIELD_NAME));

/// Runs the checks for one unsafe request.
///
/// # Errors
///
/// The refusal's code; the request is answered with 403.
pub(crate) fn check(
    csrf: &Csrf,
    req: &HttpRequest<'_>,
    binding: Option<&[u8]>,
    own_origin: &str,
    limits: &Limits,
) -> Result<State, &'static str> {
    let Some(binding) = binding.filter(|b| !b.is_empty()) else {
        return Err("csrf.no_binding");
    };
    let method = req.head().method_str();
    let mut facts = RequestFacts::new(method).own_origin(own_origin);
    if let Some(v) = req.header("sec-fetch-site") {
        facts = facts.fetch_site(v);
    }
    if let Some(v) = req.header("origin") {
        facts = facts.origin(v);
    }
    if let Some(v) = req.header("referer") {
        facts = facts.referer(v);
    }
    csrf.policy(&facts).map_err(|r| code(r.reason()))?;

    let mut headers = req.head().header_all(csrf_sec::HEADER_NAME);
    if let Some(token) = headers.next() {
        if headers.next().is_some() {
            return Err("csrf.duplicate");
        }
        return csrf
            .verify(binding, token)
            .map(|_| State::Verified)
            .map_err(|r| code(r.reason()));
    }
    let content_type = req.header("content-type").unwrap_or(b"");
    match FormKind::detect(content_type) {
        Ok(FormKind::Urlencoded) => {
            let mut check = token_check(csrf, binding);
            match form_net::parse_urlencoded_inspected(
                req.body_bytes(),
                limits,
                &Policy::DEFAULT,
                &mut check,
            ) {
                Ok(_) if check.verified() => Ok(State::Verified),
                Ok(_) => Err("csrf.missing"),
                Err(e) if e.code().starts_with("csrf.") => Err(e.code()),
                // A body that does not parse cannot carry a token.
                Err(_) => Err("csrf.unreadable_form"),
            }
        }
        Ok(FormKind::Multipart(_)) => Ok(State::Pending),
        _ => Err("csrf.missing"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codes_are_namespaced() {
        for r in [
            Reason::Missing,
            Reason::BadMac,
            Reason::CrossSite,
            Reason::Expired,
        ] {
            assert!(code(r).starts_with("csrf."));
        }
    }
}
