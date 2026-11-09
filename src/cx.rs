//! The handler's context: the cleared request, its identity, its route
//! parameters, and the reply being written.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use serve_net::{Method, Verdict};

use crate::app::Shared;
use crate::error::Error;
use crate::router::Captures;
use crate::{Output, Request, RequestId, Result, Stage, TemplateId, View, url};

/// The reply a handler writes. Held by web-net until the handler returns, so
/// an error or a panic replaces it whole: nothing a failed handler set (a
/// cookie, a header) leaves.
#[derive(Default)]
pub(crate) struct Out {
    pub(crate) status: u16,
    pub(crate) names: Vec<u8>,
    pub(crate) values: Vec<u8>,
    pub(crate) spans: Vec<(u32, u32, u32, u32)>,
    pub(crate) body: Vec<u8>,
    pub(crate) invalid: bool,
    pub(crate) has_type: bool,
}

/// Fields a handler may not set: framing is serve-net's.
const FRAMING: [&str; 5] = [
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
];

impl Out {
    pub(crate) fn reset(&mut self) {
        self.status = 200;
        self.names.clear();
        self.values.clear();
        self.spans.clear();
        self.body.clear();
        self.invalid = false;
        self.has_type = false;
    }

    pub(crate) fn wipe(&mut self) {
        // black_box keeps the zeroing from being dropped as a dead store.
        for v in [&mut self.names, &mut self.values, &mut self.body] {
            v.iter_mut().for_each(|b| *b = 0);
            std::hint::black_box(&v);
        }
    }

    pub(crate) fn header(&mut self, name: &str, value: &[u8]) {
        let ok_name = !name.is_empty()
            && name.bytes().all(is_tchar)
            && !FRAMING.iter().any(|f| f.eq_ignore_ascii_case(name));
        let ok_value = value
            .iter()
            .all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f));
        if !ok_name || !ok_value || self.spans.len() >= 64 {
            self.invalid = true;
            return;
        }
        if name.eq_ignore_ascii_case("content-type") {
            self.has_type = true;
        }
        let (ns, vs) = (self.names.len() as u32, self.values.len() as u32);
        self.names
            .extend(name.bytes().map(|b| b.to_ascii_lowercase()));
        self.values.extend_from_slice(value);
        self.spans
            .push((ns, self.names.len() as u32, vs, self.values.len() as u32));
    }

    pub(crate) fn get(&self, name: &str) -> Option<&[u8]> {
        self.spans
            .iter()
            .find(|&&(s, e, _, _)| &self.names[s as usize..e as usize] == name.as_bytes())
            .map(|&(_, _, vs, ve)| &self.values[vs as usize..ve as usize])
    }

    pub(crate) fn has(&self, name: &str) -> bool {
        self.spans
            .iter()
            .any(|&(s, e, _, _)| &self.names[s as usize..e as usize] == name.as_bytes())
    }
}

const fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'
        | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~')
}

/// A site-relative path that is safe as a redirect target: it starts with
/// one `/` (never `//` or `/\`, which browsers read as another host) and
/// holds only visible ASCII.
pub(crate) fn is_local_target(p: &str) -> bool {
    let b = p.as_bytes();
    b.first() == Some(&b'/')
        && !matches!(b.get(1), Some(b'/' | b'\\'))
        && b.iter().all(|&c| (0x21..0x7f).contains(&c) && c != b'\\')
}

/// The context a handler receives: proof that the request passed its
/// route's access check, the identity it carries, and the reply.
///
/// There is no public way to make one: web-net builds it only after the
/// gate cleared the request.
pub struct Cx<'r, I> {
    pub(crate) req: Request<'r>,
    pub(crate) who: &'r I,
    pub(crate) caps: Captures,
    pub(crate) names: &'r [Box<str>],
    pub(crate) out: &'r mut Out,
    pub(crate) shared: &'r Shared,
    pub(crate) template: Option<TemplateId>,
    pub(crate) csrf: crate::csrf::State,
    pub(crate) binding: Option<&'r [u8]>,
    pub(crate) limits: &'r form_net::Limits,
    pub(crate) before_render: &'r [crate::app::HookFn<I>],
    pub(crate) rendering: bool,
}

impl<'r, I> Cx<'r, I> {
    // ---------------------------------------------------------------- request

    /// The request.
    #[must_use]
    pub fn request(&self) -> &Request<'r> {
        &self.req
    }

    /// The method.
    #[must_use]
    pub fn method(&self) -> Method {
        self.req.method()
    }

    /// The canonical path inside the site.
    #[must_use]
    pub fn path(&self) -> &'r str {
        self.req.path
    }

    /// The first value of a request field.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&'r [u8]> {
        self.req.header(name)
    }

    /// Who the request comes from: always present, possibly a guest.
    #[must_use]
    pub fn identity(&self) -> &'r I {
        self.who
    }

    /// The request's reference, as shown on error pages.
    #[must_use]
    pub fn id(&self) -> RequestId {
        self.req.id()
    }

    /// A route parameter (`:id` or `*rest`), percent-decoded.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<Cow<'r, str>> {
        let i = self.names.iter().position(|n| n.as_ref() == name)?;
        let (s, e) = self.caps.get(i)?;
        Some(url::decode(&self.req.path[s..e]))
    }

    /// A route parameter parsed as `T`. A value that does not parse means
    /// the page does not exist (`/users/abc` for a numeric id): 404.
    ///
    /// # Errors
    ///
    /// 404 `route.param` when the parameter is missing or does not parse.
    pub fn param_as<T: FromStr>(&self, name: &str) -> Result<T> {
        self.param(name)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| Error::not_found("route.param"))
    }

    /// The first value of a query parameter, decoded (`+` is a space).
    ///
    /// # Errors
    ///
    /// 400 `query.duplicate` when the name appears twice (parameter
    /// pollution is refused, never resolved by picking one), 400
    /// `query.invalid` when the value does not decode to UTF-8.
    pub fn query(&self, name: &str) -> Result<Option<Cow<'r, str>>> {
        let Some(q) = self.req.query() else {
            return Ok(None);
        };
        let mut found = None;
        for pair in q.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if decode_query(k).as_deref() != Some(name) {
                continue;
            }
            if found.is_some() {
                return Err(Error::bad_request("query.duplicate"));
            }
            found = Some(decode_query(v).ok_or_else(|| Error::bad_request("query.invalid"))?);
        }
        Ok(found)
    }

    /// The raw request body.
    ///
    /// # Errors
    ///
    /// 403 `csrf.unverified` for a multipart body whose CSRF token has not
    /// been checked yet: read it with [`form`](Self::form) or
    /// `upload` (feature `uploads`), which check the token in the same pass.
    pub fn body(&self) -> Result<&'r [u8]> {
        if self.csrf == crate::csrf::State::Pending {
            return Err(Error::forbidden("csrf.unverified"));
        }
        Ok(self.req.http.body_bytes())
    }

    /// Reads the body as a typed form (urlencoded or multipart text fields),
    /// with the route's [`form_limits`](crate::Route::form_limits).
    ///
    /// A multipart body's CSRF token is checked in the same pass (it must
    /// come before any file part). A form type that is posted with a token
    /// lists the token field in its `ignore` list (`ignore =
    /// ["csrf_token"]`).
    ///
    /// The error keeps form-net's detail, so an action can render the form
    /// again with 422; `?` turns it into an [`Error`] with its status.
    ///
    /// ```
    /// use web_net::form_net::{self, FromForm};
    ///
    /// form_net::form! {
    ///     pub struct Signup { pub email: String }
    ///     ignore = ["csrf_token"];
    /// }
    ///
    /// let app = web_net::App::builder()
    ///     .route(web_net::post("/signup", |cx| {
    ///         let form: Signup = cx.form()?;
    ///         cx.text(200, &form.email);
    ///         Ok(())
    ///     }).public().csrf_exempt("example without a session"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app,
    ///     b"POST /signup HTTP/1.1\r\nHost: a\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nemail=a%40b.com");
    /// assert_eq!(r.text(), "a@b.com");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// form-net's [`FormError`](form_net::FormError): 415 for another media
    /// type, 413 for a budget passed, 400 for malformed input, 422 for
    /// fields that do not fit `T`, 403 for a CSRF token.
    pub fn form<T: form_net::FromForm>(&mut self) -> std::result::Result<T, form_net::FormError> {
        self.form_inspected(&mut form_net::NoInspector)
    }

    /// As [`form`](Self::form), with an inspector beside the parse (a
    /// content policy that sees every part and field first).
    ///
    /// # Errors
    ///
    /// As [`form`](Self::form), plus the inspector's refusals.
    pub fn form_inspected<T: form_net::FromForm, N: form_net::Inspector>(
        &mut self,
        inspector: &mut N,
    ) -> std::result::Result<T, form_net::FormError> {
        let content_type = self.req.header("content-type").unwrap_or(b"");
        let body = self.req.http.body_bytes();
        match (self.csrf, self.shared.csrf.as_ref(), self.binding) {
            (crate::csrf::State::Pending, Some(engine), Some(binding)) => {
                let mut check = crate::csrf::token_check(engine, binding);
                let result = T::from_body_inspected(
                    content_type,
                    body,
                    self.limits,
                    &crate::csrf::TOKEN_POLICY,
                    &mut (&mut check, inspector),
                );
                if check.verified() {
                    self.csrf = crate::csrf::State::Verified;
                }
                result
            }
            _ => T::from_body_inspected(
                content_type,
                body,
                self.limits,
                &form_net::Policy::DEFAULT,
                inspector,
            ),
        }
    }

    /// Reads a multipart upload into `store` (feature `uploads`): text
    /// fields in memory, files in the store's private temporary files, with
    /// the route's form limits. The CSRF token is checked before any file
    /// byte is stored. Turn the result into a typed form with
    /// `T::from_upload(upload)`.
    ///
    /// # Errors
    ///
    /// As [`form`](Self::form), plus the store's errors.
    #[cfg(feature = "uploads")]
    #[cfg_attr(docsrs, doc(cfg(feature = "uploads")))]
    pub fn upload(
        &mut self,
        store: &form_net::Store,
    ) -> std::result::Result<form_net::Upload, form_net::FormError> {
        self.upload_inspected(store, &mut form_net::NoInspector)
    }

    /// As [`upload`](Self::upload), with an inspector beside the parse.
    ///
    /// # Errors
    ///
    /// As [`upload`](Self::upload), plus the inspector's refusals.
    #[cfg(feature = "uploads")]
    #[cfg_attr(docsrs, doc(cfg(feature = "uploads")))]
    pub fn upload_inspected<N: form_net::Inspector>(
        &mut self,
        store: &form_net::Store,
        inspector: &mut N,
    ) -> std::result::Result<form_net::Upload, form_net::FormError> {
        let content_type = self.req.header("content-type").unwrap_or(b"");
        let body = self.req.http.body_bytes();
        match (self.csrf, self.shared.csrf.as_ref(), self.binding) {
            (crate::csrf::State::Pending, Some(engine), Some(binding)) => {
                let mut check = crate::csrf::token_check(engine, binding);
                let mut hooks = (&mut check, inspector);
                let mut session = form_net::UploadSession::new(
                    content_type,
                    self.limits,
                    &crate::csrf::TOKEN_POLICY,
                    store,
                )?;
                session.push(body, &mut hooks)?;
                let upload = session.finish(&mut hooks)?;
                if hooks.0.verified() {
                    self.csrf = crate::csrf::State::Verified;
                }
                Ok(upload)
            }
            _ => {
                let mut session = form_net::UploadSession::new(
                    content_type,
                    self.limits,
                    &form_net::Policy::DEFAULT,
                    store,
                )?;
                session.push(body, inspector)?;
                session.finish(inspector)
            }
        }
    }

    /// A CSRF token for the visitor's session, to put in a form's hidden
    /// `csrf_token` field or a script's `X-CSRF-Token` header. Different on
    /// every call (masked), so a compression side channel cannot recover it.
    ///
    /// # Errors
    ///
    /// 500 `csrf.no_engine` without [`Builder::csrf`](crate::Builder::csrf);
    /// 500 `csrf.no_binding` when the identity has no binding.
    pub fn csrf_token(&self) -> Result<String> {
        let engine = self
            .shared
            .csrf
            .as_ref()
            .ok_or_else(|| Error::internal("csrf.no_engine"))?;
        let binding = self
            .binding
            .filter(|b| !b.is_empty())
            .ok_or_else(|| Error::internal("csrf.no_binding"))?;
        engine
            .issue(binding)
            .map(|t| t.as_str().to_owned())
            .map_err(|e| Error::internal("csrf.issue").with_source(e))
    }

    /// Checks `If-Match` and `If-Unmodified-Since` against the current
    /// version of what an unsafe request would change (RFC 9110 section
    /// 13.2): `tag` is its entity tag's opaque part, `modified` its
    /// modification time. Call it before changing anything.
    ///
    /// # Errors
    ///
    /// 412 `precondition.failed` when a condition is false. Without either
    /// field, `Ok`.
    pub fn precondition(
        &self,
        tag: Option<&str>,
        modified: Option<std::time::SystemTime>,
    ) -> Result {
        let current = tag.and_then(|t| parse_net::EntityTag::strong(t.as_bytes()).ok());
        if let Some(v) = self.req.header("if-match") {
            if !parse_net::if_match(v, current.as_ref()).unwrap_or(false) {
                return Err(Error::new(412, "precondition.failed"));
            }
            return Ok(());
        }
        if let (Some(v), Some(m)) = (self.req.header("if-unmodified-since"), modified) {
            let (Ok(since), Ok(lm)) = (
                parse_net::http_date(v),
                parse_net::HttpDate::from_system_time(m),
            ) else {
                return Ok(());
            };
            if lm > since {
                return Err(Error::new(412, "precondition.failed"));
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- reply

    /// Sets the status (default 200).
    pub fn status(&mut self, status: u16) -> &mut Self {
        self.out.status = status;
        self
    }

    /// Adds a reply field. A name that is not a token, a value with a
    /// control character, or a framing field (`content-length`, ...) turns
    /// the reply into a 500 when the handler returns.
    pub fn set_header(&mut self, name: &str, value: impl AsRef<[u8]>) -> &mut Self {
        self.out.header(name, value.as_ref());
        self
    }

    /// Sets the body.
    pub fn body_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.out.body.clear();
        self.out.body.extend_from_slice(bytes);
        self
    }

    /// The best of `offers` for the request's `Accept-Language`
    /// (`["en", "fr"]`), or `None` when the request states no preference
    /// any offer meets.
    #[must_use]
    pub fn language(&self, offers: &[&'static str]) -> Option<&'static str> {
        let i = parse_net::best_language(self.req.header("accept-language"), offers)?;
        offers.get(i).copied()
    }

    /// The best of `offers` for the request's `Accept` (`["text/html",
    /// "application/json"]`).
    #[must_use]
    pub fn media(&self, offers: &[&'static str]) -> Option<&'static str> {
        let i = parse_net::best_media(self.req.header("accept"), offers)?;
        offers.get(i).copied()
    }

    /// Status, `content-type: text/html; charset=utf-8`, and the HTML.
    pub fn html(&mut self, status: u16, html: &str) -> &mut Self {
        self.content_type("text/html; charset=utf-8");
        self.status(status).body_bytes(html.as_bytes())
    }

    /// Status, `content-type: text/plain; charset=utf-8`, and the text.
    pub fn text(&mut self, status: u16, text: &str) -> &mut Self {
        self.content_type("text/plain; charset=utf-8");
        self.status(status).body_bytes(text.as_bytes())
    }

    /// Adds a `Set-Cookie` field built with cookie-net (re-exported as
    /// [`web_net::cookie_net`](crate::cookie_net)).
    ///
    /// ```
    /// use web_net::{App, get, cookie_net::SetCookie};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         cx.set_cookie(&SetCookie::new("theme", "dark").map_err(|_| web_net::Error::internal("cookie"))?);
    ///         cx.text(200, "ok");
    ///         Ok(())
    ///     }).public())
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    /// assert!(r.header("set-cookie").is_some());
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    pub fn set_cookie(&mut self, cookie: &cookie_net::SetCookie<'_>) -> &mut Self {
        let line = cookie.encode();
        self.out.header("set-cookie", line.as_bytes());
        self
    }

    /// The conditional fast path for a page: sets `ETag: "<tag>"` and, when
    /// the request's `If-None-Match` matches it (a `GET` or `HEAD`), turns the
    /// reply into `304 Not Modified` and returns `true`, so the handler
    /// returns before building the page.
    ///
    /// `tag` is the opaque part (letters, digits, and `-._~` are safe), for
    /// example a revision number. An unusable tag sets nothing and returns
    /// `false`.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         if cx.not_modified("rev-7") {
    ///             return Ok(());
    ///         }
    ///         cx.html(200, "<h1>page</h1>");
    ///         Ok(())
    ///     }).public())
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: a\r\nIf-None-Match: \"rev-7\"\r\n\r\n");
    /// assert_eq!(r.status, 304);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    pub fn not_modified(&mut self, tag: &str) -> bool {
        let Ok(current) = parse_net::EntityTag::strong(tag.as_bytes()) else {
            return false;
        };
        let quoted = format!("\"{tag}\"");
        self.out.header("etag", quoted.as_bytes());
        if !matches!(self.method(), Method::Get | Method::Head) {
            return false;
        }
        let matched = self
            .req
            .header("if-none-match")
            .is_some_and(|v| parse_net::if_none_match(v, &current).unwrap_or(false));
        if matched {
            self.out.status = 304;
            self.out.body.clear();
        }
        matched
    }

    fn content_type(&mut self, value: &str) {
        if !self.out.has_type {
            self.out.header("content-type", value.as_bytes());
        }
    }

    /// The site-relative `path` as a URL path: the site's base path in
    /// front (`/blog` + `/posts/1`). Every link a page writes goes through
    /// this, so the site works installed in a folder.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        let base = self.shared.base.as_ref();
        if path == "/" && !base.is_empty() {
            format!("{base}/")
        } else {
            format!("{base}{path}")
        }
    }

    /// `303 See Other` to a site-relative path: the answer to a form that
    /// was accepted, so a reload does not post it again.
    ///
    /// # Errors
    ///
    /// 500 `redirect.not_local` when `path` is not a local path (it must
    /// start with one `/`): redirects to other hosts are never built from a
    /// string a handler passes along.
    pub fn see_other(&mut self, path: &str) -> Result {
        self.redirect(303, path)
    }

    /// A redirect to another site, only to a host listed with
    /// [`Builder::redirect_hosts`](crate::Builder::redirect_hosts):
    /// `https://` (or `http://`), the host, and a visible-ASCII rest.
    ///
    /// # Errors
    ///
    /// 500 `redirect.not_allowed` for any other target, 500
    /// `redirect.status` for a status that is not a redirect.
    pub fn redirect_external(&mut self, status: u16, url: &str) -> Result {
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            return Err(Error::internal("redirect.status"));
        }
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .ok_or_else(|| Error::internal("redirect.not_allowed"))?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = rest[..end].to_ascii_lowercase();
        let host = authority
            .rsplit_once(':')
            .map_or(authority.as_str(), |(h, p)| {
                if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() {
                    h
                } else {
                    ""
                }
            });
        let listed = self
            .shared
            .redirect_hosts
            .iter()
            .any(|h| h.as_ref() == authority || h.as_ref() == host);
        let visible = url.bytes().all(|c| (0x21..0x7f).contains(&c) && c != b'\\');
        if !listed || !visible || authority.contains('@') {
            return Err(Error::internal("redirect.not_allowed"));
        }
        self.out.header("location", url.as_bytes());
        self.out.status = status;
        self.out.body.clear();
        Ok(())
    }

    /// A redirect with `status` (301, 302, 303, 307, 308) to a
    /// site-relative path.
    ///
    /// # Errors
    ///
    /// As [`see_other`](Self::see_other); 500 `redirect.status` for a
    /// status that is not a redirect.
    pub fn redirect(&mut self, status: u16, path: &str) -> Result {
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            return Err(Error::internal("redirect.status"));
        }
        if !is_local_target(path) {
            return Err(Error::internal("redirect.not_local"));
        }
        let location = self.url(path);
        self.out.header("location", location.as_bytes());
        self.out.status = status;
        self.out.body.clear();
        Ok(())
    }

    /// Renders the route's template (declared with
    /// [`Route::template`](crate::Route::template)) against `view` into the
    /// body. The status stays as set (200 by default); `content-type` is
    /// HTML unless the handler set one.
    ///
    /// # Errors
    ///
    /// 500 `render.no_engine` or `render.no_template` when nothing can
    /// render; the engine's own [`RenderError`](crate::RenderError) as a 500;
    /// a checkpoint's denial.
    pub fn render(&mut self, view: &dyn View) -> Result {
        let t = self
            .template
            .ok_or_else(|| Error::internal("render.no_template"))?;
        self.render_id(t, view)
    }

    /// Renders the template `name` against `view`. The name is resolved by
    /// the engine on every call; prefer [`render`](Self::render) with a
    /// template declared on the route, resolved once at build.
    ///
    /// # Errors
    ///
    /// As [`render`](Self::render).
    pub fn render_named(&mut self, name: &str, view: &dyn View) -> Result {
        let engine = self
            .shared
            .render
            .as_deref()
            .ok_or_else(|| Error::internal("render.no_engine"))?;
        let t = engine
            .template(name)
            .ok_or_else(|| Error::internal("render.no_template"))?;
        self.render_id(t, view)
    }

    fn render_id(&mut self, t: TemplateId, view: &dyn View) -> Result {
        let engine = self
            .shared
            .render
            .as_deref()
            .ok_or_else(|| Error::internal("render.no_engine"))?;
        if !self.rendering {
            // Hooks may render too; they do not run their own hooks again.
            self.rendering = true;
            let hooks = self.before_render;
            let ran = hooks.iter().try_for_each(|h| h(self));
            self.rendering = false;
            ran?;
        }
        if let Some(cp) = &self.shared.checkpoint {
            match cp.check(self.req.env, Stage::BeforeRender) {
                Verdict::Pass => {}
                Verdict::Deny { status } => return Err(Error::new(status, "checkpoint.denied")),
                _ => return Err(Error::forbidden("checkpoint.killed")),
            }
        }
        self.out.body.clear();
        let mut output = Output::new(&mut self.out.body, self.shared.page_limit);
        let rendered = engine.render(t, view, &mut output);
        if let Err(e) = rendered {
            self.out.body.clear();
            return Err(e.into());
        }
        self.content_type("text/html; charset=utf-8");
        Ok(())
    }
}

impl<I> fmt::Debug for Cx<'_, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cx")
            .field("request", &self.req)
            .field("status", &self.out.status)
            .finish_non_exhaustive()
    }
}

/// Decodes one query name or value: `+` is a space, escapes decoded once.
fn decode_query(s: &str) -> Option<Cow<'_, str>> {
    if !s.contains(['%', '+']) {
        return Some(Cow::Borrowed(s));
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let h = b.get(i + 1).and_then(|&c| (c as char).to_digit(16))?;
                let l = b.get(i + 2).and_then(|&c| (c as char).to_digit(16))?;
                out.push(((h << 4) | l) as u8);
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok().map(Cow::Owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_targets() {
        for ok in ["/", "/a", "/a/b?c=d", "/a%20b"] {
            assert!(is_local_target(ok), "{ok}");
        }
        for bad in [
            "",
            "a",
            "//evil.example",
            "/\\evil.example",
            "https://x",
            "/a\r\nx",
            "/a b",
            "/a\\b",
        ] {
            assert!(!is_local_target(bad), "{bad:?}");
        }
    }

    #[test]
    fn test_decode_query() {
        assert_eq!(decode_query("a+b%21").as_deref(), Some("a b!"));
        assert_eq!(decode_query("plain").as_deref(), Some("plain"));
        assert_eq!(decode_query("%zz"), None);
        assert_eq!(decode_query("%ff"), None);
    }

    #[test]
    fn test_out_refuses_bad_fields() {
        let mut o = Out::default();
        o.header("x-ok", b"v");
        assert!(!o.invalid);
        o.header("content-length", b"1");
        assert!(o.invalid);
        let mut o = Out::default();
        o.header("x", b"a\r\nb");
        assert!(o.invalid);
        let mut o = Out::default();
        o.header("bad name", b"v");
        assert!(o.invalid);
        let mut o = Out::default();
        o.header("Content-Type", b"text/x");
        assert!(o.has_type && o.has("content-type"));
    }
}
