//! Errors: what a handler returns, and what a build refuses.
//!
//! Every refusal and error becomes a response through one function: the
//! status, the site's error template for it (or a built-in page that cannot
//! fail), a generic message, and the request's reference. The code and the
//! detail go to the events only.

use std::fmt;

type Source = Box<dyn std::error::Error + Send + Sync>;

/// A handler error: a status, a stable code, and an optional source kept for
/// the logs. The visitor sees the status, a generic message, and the
/// request's reference; never the code or the source.
///
/// ```
/// use web_net::Error;
///
/// let e = Error::not_found("blog.no_post");
/// assert_eq!((e.status(), e.code()), (404, "blog.no_post"));
///
/// let io = std::io::Error::other("disk gone");
/// let e = Error::internal("blog.read").with_source(io);
/// assert_eq!(e.status(), 500);
/// assert!(e.source_ref().is_some());
/// ```
pub struct Error {
    status: u16,
    code: &'static str,
    source: Option<Source>,
}

impl Error {
    /// An error with `status` (400 to 599; anything else is treated as 500).
    #[must_use]
    pub fn new(status: u16, code: &'static str) -> Self {
        let status = if (400..=599).contains(&status) {
            status
        } else {
            500
        };
        Self {
            status,
            code,
            source: None,
        }
    }

    /// 400 Bad Request.
    #[must_use]
    pub fn bad_request(code: &'static str) -> Self {
        Self::new(400, code)
    }

    /// 403 Forbidden.
    #[must_use]
    pub fn forbidden(code: &'static str) -> Self {
        Self::new(403, code)
    }

    /// 404 Not Found.
    #[must_use]
    pub fn not_found(code: &'static str) -> Self {
        Self::new(404, code)
    }

    /// 409 Conflict.
    #[must_use]
    pub fn conflict(code: &'static str) -> Self {
        Self::new(409, code)
    }

    /// 422 Unprocessable Content: the request was understood and refused
    /// (a form with errors).
    #[must_use]
    pub fn unprocessable(code: &'static str) -> Self {
        Self::new(422, code)
    }

    /// 500 Internal Server Error: our fault, not the visitor's.
    #[must_use]
    pub fn internal(code: &'static str) -> Self {
        Self::new(500, code)
    }

    /// 503 Service Unavailable.
    #[must_use]
    pub fn unavailable(code: &'static str) -> Self {
        Self::new(503, code)
    }

    /// Keeps `source` for the logs.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<Source>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// The status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// The code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The source, if one was kept.
    #[must_use]
    pub fn source_ref(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.source.as_deref()
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("status", &self.status)
            .field("code", &self.code)
            .field("source", &self.source.as_ref().map(|s| s.to_string()))
            .finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.status, self.code)?;
        if let Some(s) = &self.source {
            write!(f, ": {s}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|s| s as &(dyn std::error::Error + 'static))
    }
}

impl From<crate::Denial> for Error {
    fn from(d: crate::Denial) -> Self {
        Self::new(d.status_code(), d.code())
    }
}

impl From<form_net::FormError> for Error {
    /// The form's status (400, 413, 415, 422, or 403 for a token) and code.
    fn from(e: form_net::FormError) -> Self {
        Self::new(e.status_hint(), e.code()).with_source(e)
    }
}

impl From<crate::RenderError> for Error {
    fn from(e: crate::RenderError) -> Self {
        Self::internal(e.code()).with_source(e)
    }
}

/// The handler result.
pub type Result<T = (), E = Error> = std::result::Result<T, E>;

/// One thing wrong with an application's declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The route or setting it is about (`"GET /admin"`, `"host"`).
    pub subject: String,
    /// What is wrong and what to do.
    pub message: String,
}

/// Why [`Builder::build`](crate::Builder::build) refused: every problem
/// found, not only the first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildError {
    problems: Vec<Problem>,
}

impl BuildError {
    pub(crate) fn new(problems: Vec<Problem>) -> Self {
        Self { problems }
    }

    /// The problems, in declaration order.
    #[must_use]
    pub fn problems(&self) -> &[Problem] {
        &self.problems
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the application has {} problem(s):", self.problems.len())?;
        for p in &self.problems {
            write!(f, "\n  {}: {}", p.subject, p.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for BuildError {}

/// The generic reason phrase shown for a status.
pub(crate) fn title(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        s if s < 500 => "Request Refused",
        _ => "Server Error",
    }
}

/// The generic message shown for a status.
pub(crate) fn message(status: u16) -> &'static str {
    match status {
        400 => "The request could not be understood.",
        401 => "Please sign in to continue.",
        403 => "You do not have access to this page.",
        404 => "The page was not found.",
        405 => "This page does not accept that kind of request.",
        421 => "This server does not serve that address.",
        422 => "The request could not be processed.",
        429 => "Too many requests. Please wait a moment and try again.",
        503 => "The service is unavailable right now. Please try again shortly.",
        s if s < 500 => "The request was refused.",
        _ => "Something went wrong on our side.",
    }
}

/// The built-in error page: fixed markup, the status, its title and message,
/// and the reference. Nothing from the request appears in it except the
/// reference, which web-net makes itself.
pub(crate) fn builtin_page(status: u16, reference: &str, out: &mut Vec<u8>) {
    let t = title(status);
    out.extend_from_slice(
        b"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>",
    );
    push_status(status, out);
    out.push(b' ');
    out.extend_from_slice(t.as_bytes());
    out.extend_from_slice(
        b"</title><meta name=\"viewport\" content=\"width=device-width\"></head>\n<body><h1>",
    );
    out.extend_from_slice(t.as_bytes());
    out.extend_from_slice(b"</h1><p>");
    out.extend_from_slice(message(status).as_bytes());
    out.extend_from_slice(b"</p><p><small>Reference: ");
    out.extend_from_slice(reference.as_bytes());
    out.extend_from_slice(b"</small></p></body></html>\n");
}

/// The error reply for a client that prefers JSON: the same facts as the
/// page, no detail.
pub(crate) fn json_body(status: u16, reference: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(b"{\"status\":");
    push_status(status, out);
    out.extend_from_slice(b",\"title\":\"");
    out.extend_from_slice(title(status).as_bytes());
    out.extend_from_slice(b"\",\"message\":\"");
    out.extend_from_slice(message(status).as_bytes());
    out.extend_from_slice(b"\",\"reference\":\"");
    // The reference is hex digits, a dash, and digits: nothing to escape.
    out.extend_from_slice(reference.as_bytes());
    out.extend_from_slice(b"\"}");
}

fn push_status(status: u16, out: &mut Vec<u8>) {
    let s = status.min(999);
    out.push(b'0' + (s / 100) as u8);
    out.push(b'0' + (s / 10 % 10) as u8);
    out.push(b'0' + (s % 10) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_clamped() {
        assert_eq!(Error::new(200, "x").status(), 500);
        assert_eq!(Error::new(302, "x").status(), 500);
        assert_eq!(Error::new(418, "x").status(), 418);
    }

    #[test]
    fn test_builtin_page_has_no_detail() {
        let mut out = Vec::new();
        builtin_page(404, "c7-r2", &mut out);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("<title>404 Not Found</title>"));
        assert!(s.contains("Reference: c7-r2"));
    }

    #[test]
    fn test_build_error_lists_all() {
        let e = BuildError::new(vec![
            Problem {
                subject: "GET /".into(),
                message: "a".into(),
            },
            Problem {
                subject: "GET /b".into(),
                message: "b".into(),
            },
        ]);
        assert_eq!(e.problems().len(), 2);
        assert!(e.to_string().contains("2 problem(s)"));
    }
}
