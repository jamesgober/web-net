//! The handler's context: the cleared request, its identity, its route
//! parameters, and the reply being written.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use serve_net::{Method, Verdict};

use crate::app::Shared;
use crate::error::Error;
use crate::router::Captures;
use crate::{NoRender, Output, Render, Request, RequestId, Result, Stage, TemplateId, View, url};

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

    /// Drops every field called `name`.
    pub(crate) fn remove(&mut self, name: &str) {
        let names = &self.names;
        self.spans
            .retain(|&(s, e, _, _)| &names[s as usize..e as usize] != name.as_bytes());
    }

    /// Whether a `Set-Cookie` field sets the cookie `cookie` (by name).
    pub(crate) fn sets_cookie(&self, cookie: &str) -> bool {
        let name = cookie.split('=').next().unwrap_or("").trim();
        self.spans.iter().any(|&(s, e, vs, ve)| {
            &self.names[s as usize..e as usize] == b"set-cookie"
                && self.values[vs as usize..ve as usize]
                    .split(|&b| b == b'=')
                    .next()
                    .is_some_and(|n| n.trim_ascii() == name.as_bytes())
        })
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

/// `path` inside a site installed under `base` (`""` or `/blog`).
pub(crate) fn site_url(base: &str, path: &str) -> String {
    if path == "/" && !base.is_empty() {
        format!("{base}/")
    } else {
        format!("{base}{path}")
    }
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
///
/// ```
/// use web_net::{App, Context, Guest, get};
///
/// fn home(cx: &mut Context<'_, Guest>) -> web_net::Result {
///     cx.text(200, "home")
/// }
///
/// let app = App::builder().route(get("/", home)).build()?;
/// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.text(), "home");
/// # Ok::<(), web_net::BuildError>(())
/// ```
pub struct Context<'r, I, E: Render = NoRender> {
    pub(crate) req: Request<'r>,
    pub(crate) who: &'r I,
    pub(crate) caps: Captures,
    pub(crate) names: &'r [Box<str>],
    pub(crate) out: &'r mut Out,
    pub(crate) shared: &'r Shared<E>,
    pub(crate) template: Option<TemplateId>,
    pub(crate) binding: Option<&'r [u8]>,
    pub(crate) limits: &'r form_net::Limits,
    pub(crate) before_render: &'r [crate::app::HookFn<I, E>],
    pub(crate) rendering: bool,
}

impl<'r, I, E: Render> Context<'r, I, E> {
    // ---------------------------------------------------------------- request

    /// The request.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let host = cx.request().host();
    ///         cx.text(200, host)
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "localhost");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn request(&self) -> &Request<'r> {
        &self.req
    }

    /// The method.
    ///
    /// ```
    /// use serve_net::Method;
    /// use web_net::{App, Context, Guest, Route};
    ///
    /// fn which(cx: &mut Context<'_, Guest>) -> web_net::Result {
    ///     let m = if cx.method() == Method::Post { "post" } else { "get" };
    ///     cx.text(200, m)
    /// }
    ///
    /// let app = App::builder()
    ///     .route(Route::at("/").get(which).post(which).csrf_exempt("example"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    /// assert_eq!(r.text(), "post");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn method(&self) -> Method {
        self.req.method()
    }

    /// The canonical path inside the site.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .base("/app")
    ///     .route(get("/about", |cx| cx.text(200, cx.path())))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /app/about HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "/about");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn path(&self) -> &'r str {
        self.req.path
    }

    /// The first value of a request field.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let agent = cx.header("user-agent").unwrap_or(b"unknown");
    ///         cx.bytes(200, "text/plain", agent)
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: demo/1\r\n\r\n");
    /// assert_eq!(r.text(), "demo/1");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&'r [u8]> {
        self.req.header(name)
    }

    /// Who the request comes from: always present, possibly a guest.
    ///
    /// ```
    /// use web_net::{App, Context, Guest, Identity, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx: &mut Context<'_, Guest>| {
    ///         let who = if cx.identity().is_guest() { "guest" } else { "member" };
    ///         cx.text(200, who)
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "guest");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn identity(&self) -> &'r I {
        self.who
    }

    /// The request's reference, as shown on error pages.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let reference = cx.id().to_string();
    ///         cx.text(200, &reference)
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text().len(), 16);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn id(&self) -> RequestId {
        self.req.id()
    }

    /// A route parameter (`:slug` or `*rest`), percent-decoded.
    ///
    /// The path is canonical (no dot segments), but a `*rest` value is part
    /// of a URL, not a safe file path: it can hold a drive (`C:/Windows`)
    /// or names a file system reads specially. Serve files with
    /// [`Assets`](crate::Assets), which refuses those; never join a
    /// parameter onto a folder.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/posts/:slug", |cx| cx.text(200, &cx.param("slug")?)))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /posts/hello%20world HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "hello world");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// 500 `route.no_param` when the route's pattern has no parameter
    /// `name` (a mistake in the handler).
    pub fn param(&self, name: &str) -> Result<Cow<'r, str>> {
        let i = self
            .names
            .iter()
            .position(|n| n.as_ref() == name)
            .ok_or_else(|| Error::internal("route.no_param"))?;
        let (s, e) = self
            .caps
            .get(i)
            .ok_or_else(|| Error::internal("route.no_param"))?;
        Ok(url::decode(&self.req.path[s..e]))
    }

    /// A route parameter parsed as `T`. A value that does not parse means
    /// the page does not exist (`/users/abc` for a numeric id): 404.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/users/:id", |cx| {
    ///         let id: u64 = cx.param_as("id")?;
    ///         cx.text(200, &format!("user {id}"))
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /users/abc HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.status, 404);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// 404 `route.param` when the value does not parse; as
    /// [`param`](Self::param) for a name the pattern does not have.
    pub fn param_as<T: FromStr>(&self, name: &str) -> Result<T> {
        self.param(name)?
            .parse()
            .map_err(|_| Error::not_found("route.param"))
    }

    /// The first value of a query parameter, decoded (`+` is a space).
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/search", |cx| {
    ///         let q = cx.query("q")?.unwrap_or_default();
    ///         cx.text(200, &q)
    ///     }))
    ///     .build()?;
    /// let at = |target: &str| serve_net::testing::respond(&app, format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes());
    /// assert_eq!(at("/search?q=red+shoes").text(), "red shoes");
    /// assert_eq!(at("/search?q=a&q=b").status, 400);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
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

    /// The raw request body. On an unsafe method its CSRF token was
    /// checked before the handler ran.
    ///
    /// ```
    /// use web_net::{App, post};
    ///
    /// let app = App::builder()
    ///     .route(post("/echo", |cx| {
    ///         let body = cx.body()?;
    ///         cx.bytes(200, "text/plain", body)
    ///     }).csrf_exempt("example: echoes the body"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello");
    /// assert_eq!(r.text(), "hello");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// None today; reading the body stays fallible so a content inspector
    /// can refuse it in a later version without changing handlers.
    pub fn body(&self) -> Result<&'r [u8]> {
        Ok(self.req.http.body_bytes())
    }

    /// Reads the body as a typed form (urlencoded or multipart text fields),
    /// with the route's [`form_limits`](crate::Route::form_limits).
    ///
    /// On an unsafe method the CSRF token was checked before the handler
    /// ran. A form type that is posted with a token lists the token field in
    /// its `ignore` list (`ignore = ["csrf_token"]`).
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
    ///         cx.text(200, &form.email)
    ///     }).csrf_exempt("example without a session"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app,
    ///     b"POST /signup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nemail=a%40b.com");
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
    /// ```
    /// use web_net::form_net::{self, FromForm, Inspector, Refusal, Verdict};
    ///
    /// form_net::form! {
    ///     pub struct Signup { pub email: String }
    ///     ignore = ["csrf_token"];
    /// }
    ///
    /// /// Refuses addresses at one domain.
    /// struct NoSpam;
    /// impl Inspector for NoSpam {
    ///     fn field(&mut self, name: &str, value: &[u8]) -> Verdict {
    ///         if name == "email" && value.ends_with(b"@spam.example") {
    ///             return Verdict::Refuse(Refusal::new(422, "signup.spam"));
    ///         }
    ///         Verdict::Continue
    ///     }
    /// }
    ///
    /// let app = web_net::App::builder()
    ///     .route(web_net::post("/signup", |cx| {
    ///         let form: Signup = cx.form_inspected(&mut NoSpam)?;
    ///         cx.text(200, &form.email)
    ///     }).csrf_exempt("example without a session"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app,
    ///     b"POST /signup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 22\r\n\r\nemail=a%40spam.example");
    /// assert_eq!(r.status, 422);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
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
        T::from_body_inspected(
            content_type,
            body,
            self.limits,
            &form_net::Policy::DEFAULT,
            inspector,
        )
    }

    /// Reads a multipart upload into `store` (feature `uploads`): text
    /// fields in memory, files in the store's private temporary files, with
    /// the route's form limits. The CSRF token was checked before the
    /// handler ran, so a forged one stores nothing. Turn the result into a typed form with
    /// `T::from_upload(upload)`.
    ///
    /// ```
    /// use web_net::form_net::Store;
    ///
    /// let store = Store::memory_only();
    /// let app = web_net::App::builder()
    ///     .route(web_net::post("/upload", move |cx| {
    ///         let upload = cx.upload(&store)?;
    ///         let stored = upload.file("photo").is_some();
    ///         cx.text(200, if stored { "stored" } else { "none" })
    ///     }).csrf_exempt("example without a session"))
    ///     .build()?;
    /// let body = "--XyZ\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nabc\r\n--XyZ--\r\n";
    /// let req = format!("POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=XyZ\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    /// let r = serve_net::testing::respond(&app, req.as_bytes());
    /// assert_eq!(r.text(), "stored");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
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
    /// ```
    /// use web_net::form_net::{Inspector, PartHead, Refusal, Store, Verdict};
    ///
    /// /// Takes text fields only.
    /// struct NoFiles;
    /// impl Inspector for NoFiles {
    ///     fn part_start(&mut self, head: &PartHead<'_>) -> Verdict {
    ///         if head.is_file() {
    ///             return Verdict::Refuse(Refusal::new(422, "upload.no_files"));
    ///         }
    ///         Verdict::Continue
    ///     }
    /// }
    ///
    /// let store = Store::memory_only();
    /// let app = web_net::App::builder()
    ///     .route(web_net::post("/upload", move |cx| {
    ///         let _upload = cx.upload_inspected(&store, &mut NoFiles)?;
    ///         cx.text(200, "ok")
    ///     }).csrf_exempt("example without a session"))
    ///     .build()?;
    /// let body = "--XyZ\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"a.txt\"\r\n\r\nabc\r\n--XyZ--\r\n";
    /// let req = format!("POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=XyZ\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    /// let r = serve_net::testing::respond(&app, req.as_bytes());
    /// assert_eq!(r.status, 422);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
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
        let mut session = form_net::UploadSession::new(
            content_type,
            self.limits,
            &form_net::Policy::DEFAULT,
            store,
        )?;
        session.push(body, inspector)?;
        session.finish(inspector)
    }

    /// A CSRF token for the visitor's session, to put in a form's hidden
    /// `csrf_token` field or a script's `X-CSRF-Token` header. Different on
    /// every call (masked), so a compression side channel cannot recover it.
    ///
    /// ```
    /// use web_net::{App, Context, Denial, Gate, Identity, Request, csrf_sec::Csrf, get};
    ///
    /// struct Visitor;
    /// impl Identity for Visitor {
    ///     fn is_guest(&self) -> bool { false }
    ///     fn csrf_binding(&self) -> Option<&[u8]> { Some(b"the session id") }
    /// }
    /// # struct Sessions;
    /// # impl Gate for Sessions {
    /// #     type Identity = Visitor;
    /// #     type Rule = ();
    /// #     fn authenticate(&self, _: &Request<'_>) -> Result<Visitor, Denial> { Ok(Visitor) }
    /// #     fn authorize(&self, _: &Visitor, _: &(), _: &Request<'_>) -> Result<(), Denial> { Ok(()) }
    /// # }
    ///
    /// // `Sessions` is a gate whose identity is `Visitor`.
    /// let app = App::with_gate(Sessions)
    ///     .csrf(Csrf::new(*b"a persisted 32-byte secret key!!").unwrap())
    ///     .route(get("/form", |cx: &mut Context<'_, Visitor>| {
    ///         let token = cx.csrf_token()?;
    ///         cx.html(200, &format!("<input type=hidden name=csrf_token value=\"{token}\">"))
    ///     }).public())
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /form HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert!(r.text().starts_with("<input type=hidden name=csrf_token value=\""));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
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
    /// ```
    /// use web_net::{App, put};
    ///
    /// let app = App::builder()
    ///     .route(put("/doc", |cx| {
    ///         cx.precondition(Some("v2"), None)?; // the stored version is "v2"
    ///         cx.text(200, "saved")
    ///     }).csrf_exempt("example"))
    ///     .build()?;
    /// let send = |tag: &str| serve_net::testing::respond(&app, format!("PUT /doc HTTP/1.1\r\nHost: localhost\r\nIf-Match: \"{tag}\"\r\nContent-Length: 0\r\n\r\n").as_bytes()).status;
    /// assert_eq!(send("v1"), 412);
    /// assert_eq!(send("v2"), 200);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
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

    /// Sets the status (default 200) for a reply written by
    /// [`render`](Self::render) or [`reply_buffer`](Self::reply_buffer);
    /// [`html`](Self::html), [`text`](Self::text), and [`bytes`](Self::bytes)
    /// take theirs as an argument.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         cx.status(202).set_header("content-type", "text/plain");
    ///         cx.reply_buffer().extend_from_slice(b"queued");
    ///         Ok(())
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!((r.status, r.text()), (202, "queued"));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    pub fn status(&mut self, status: u16) -> &mut Self {
        self.out.status = status;
        self
    }

    /// Adds a reply field. A name that is not a token, a value with a
    /// control character, or a framing field (`content-length`, ...) turns
    /// the reply into a 500 when the handler returns.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         cx.set_header("x-version", "7");
    ///         cx.text(200, "ok")
    ///     }))
    ///     .route(get("/bad", |cx| {
    ///         cx.set_header("content-length", "1"); // framing is serve-net's
    ///         cx.text(200, "ok")
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("x-version"), Some(&b"7"[..]));
    /// let r = serve_net::testing::respond(&app, b"GET /bad HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.status, 500);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    pub fn set_header(&mut self, name: &str, value: impl AsRef<[u8]>) -> &mut Self {
        self.out.header(name, value.as_ref());
        self
    }

    /// Status, `content_type`, and the body. A `content-type` the handler
    /// set with [`set_header`](Self::set_header) wins.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/logo.svg", |cx| cx.bytes(200, "image/svg+xml", b"<svg/>")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /logo.svg HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("content-type"), Some(&b"image/svg+xml"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// None; it returns [`Result`] so a handler can end with it.
    pub fn bytes(&mut self, status: u16, content_type: &str, body: &[u8]) -> Result {
        self.content_type(content_type);
        self.out.status = status;
        self.out.body.clear();
        self.out.body.extend_from_slice(body);
        Ok(())
    }

    /// Status, `content-type: text/html; charset=utf-8`, and the HTML.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| cx.html(200, "<h1>Hello</h1>")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!((r.status, r.text()), (200, "<h1>Hello</h1>"));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// None; it returns [`Result`] so a handler can end with it.
    pub fn html(&mut self, status: u16, html: &str) -> Result {
        self.bytes(status, "text/html; charset=utf-8", html.as_bytes())
    }

    /// Status, `content-type: text/plain; charset=utf-8`, and the text.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder().route(get("/", |cx| cx.text(200, "ok"))).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "ok");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// None; it returns [`Result`] so a handler can end with it.
    pub fn text(&mut self, status: u16, text: &str) -> Result {
        self.bytes(status, "text/plain; charset=utf-8", text.as_bytes())
    }

    /// The reply body's buffer, emptied, for a writer that appends to a
    /// `Vec<u8>` (a template engine with its own API writing straight in).
    /// Set the status with [`status`](Self::status) and `content-type` with
    /// [`set_header`](Self::set_header); the page budget does not apply here.
    ///
    /// ```
    /// use std::io::Write;
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         write!(cx.reply_buffer(), "{} + {} = {}", 1, 2, 3).map_err(|_| web_net::Error::internal("write"))?;
    ///         cx.set_header("content-type", "text/plain");
    ///         Ok(())
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "1 + 2 = 3");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    pub fn reply_buffer(&mut self) -> &mut Vec<u8> {
        self.out.body.clear();
        &mut self.out.body
    }

    /// The best of `offers` for the request's `Accept` (`["text/html",
    /// "application/json"]`), or `None` when the request accepts none of
    /// them.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| match cx.accept(&["text/html", "application/json"]) {
    ///         Some("application/json") => cx.bytes(200, "application/json", b"{}"),
    ///         _ => cx.html(200, "<p>hi</p>"),
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n");
    /// assert_eq!(r.text(), "{}");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn accept(&self, offers: &[&'static str]) -> Option<&'static str> {
        let i = parse_net::best_media(self.req.header("accept"), offers)?;
        offers.get(i).copied()
    }

    /// The best of `offers` for the request's `Accept-Language`
    /// (`["en", "fr"]`), or `None` when the request states no preference
    /// any offer meets.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| {
    ///         let lang = cx.accept_language(&["en", "fr"]).unwrap_or("en");
    ///         cx.text(200, lang)
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Language: fr-CA, en;q=0.5\r\n\r\n");
    /// assert_eq!(r.text(), "fr");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn accept_language(&self, offers: &[&'static str]) -> Option<&'static str> {
        let i = parse_net::best_language(self.req.header("accept-language"), offers)?;
        offers.get(i).copied()
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
    ///         cx.text(200, "ok")
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
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
    ///         cx.html(200, "<h1>page</h1>")
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: \"rev-7\"\r\n\r\n");
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

    /// The site path `path` as a URL path: the site's base path in front
    /// (`/blog` + `/posts/1`), so the site works installed in a folder.
    /// `path` is used as it is (a query and a fragment included); for a
    /// path built from a visitor's input, use [`url_path`](Self::url_path),
    /// which encodes each segment.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .base("/blog")
    ///     .route(get("/", |cx| {
    ///         let about = cx.url("/about")?;
    ///         cx.html(200, &format!("<a href=\"{about}\">about</a>"))
    ///     }))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /blog/ HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "<a href=\"/blog/about\">about</a>");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// 500 `url.not_local` when `path` is not a path of this site: it must
    /// start with one `/` (never `//` or `/\`, which browsers read as
    /// another host) and hold only visible ASCII.
    pub fn url(&self, path: &str) -> Result<String> {
        if !is_local_target(path) {
            return Err(Error::internal("url.not_local"));
        }
        Ok(site_url(&self.shared.base, path))
    }

    /// A URL path from segments, each percent-encoded as a path segment, the
    /// base path in front: `["tags", tag]` gives `/blog/tags/a%2Fb` for the
    /// tag `a/b`. A segment cannot add a path level, a query, a fragment, or
    /// another host (`/`, `?`, `#`, `%`, and spaces are encoded; characters a
    /// path segment allows, such as `&` and `+`, stay).
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .route(get("/", |cx| cx.text(200, &cx.url_path(&["tags", "c# & c++"]))))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "/tags/c%23%20&%20c++");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    #[must_use]
    pub fn url_path(&self, segments: &[&str]) -> String {
        let mut out = String::from(&*self.shared.base);
        for s in segments {
            out.push('/');
            url::encode_segment(s.as_bytes(), &mut out);
        }
        if out.is_empty() || segments.is_empty() {
            out.push('/');
        }
        out
    }

    /// The page a sign-in redirect asked for: the `next` query parameter
    /// web-net puts on the redirect to the sign-in page, as a site-relative
    /// path safe to pass to [`redirect`](Self::redirect) once the visitor
    /// signed in. `None` when there is none, or when it is not a path of this
    /// site (an attacker's link to the sign-in page cannot turn it into an
    /// open redirect).
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .base("/app")
    ///     .route(get("/login", |cx| {
    ///         let next = cx.next_path()?.unwrap_or_else(|| "/".into());
    ///         cx.text(200, &next)
    ///     }))
    ///     .build()?;
    /// let at = |q: &str| serve_net::testing::respond(&app, format!("GET /app/login?{q} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()).text().to_owned();
    /// assert_eq!(at("next=/app/account%3Ftab%3D2"), "/account?tab=2");
    /// assert_eq!(at("next=//evil.example"), "/");
    /// assert_eq!(at("next=/elsewhere"), "/");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`query`](Self::query): 400 when `next` is given twice or does not
    /// decode.
    pub fn next_path(&self) -> Result<Option<String>> {
        let Some(next) = self.query("next")? else {
            return Ok(None);
        };
        let base = self.shared.base.as_ref();
        let rel = if base.is_empty() {
            next.as_ref()
        } else {
            match next.strip_prefix(base) {
                Some("") => "/",
                Some(r) if r.starts_with('/') => r,
                _ => return Ok(None),
            }
        };
        Ok(is_local_target(rel).then(|| rel.to_owned()))
    }

    /// A redirect to another site, only to a host listed with
    /// [`Builder::redirect_hosts`](crate::Builder::redirect_hosts):
    /// `https://` (or `http://`), the host, and a visible-ASCII rest.
    ///
    /// ```
    /// use web_net::{App, get};
    ///
    /// let app = App::builder()
    ///     .redirect_hosts(&["docs.example.com"])
    ///     .route(get("/docs", |cx| cx.redirect_external(302, "https://docs.example.com/start")))
    ///     .route(get("/away", |cx| cx.redirect_external(302, "https://elsewhere.example/")))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /docs HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("location"), Some(&b"https://docs.example.com/start"[..]));
    /// let r = serve_net::testing::respond(&app, b"GET /away HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.status, 500);
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
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

    /// A redirect with `status` to a site-relative path, the site's base
    /// path put in front. 303 answers a form that was accepted, so a reload
    /// does not post it again; 301 and 308 are permanent; 302 and 307
    /// temporary.
    ///
    /// ```
    /// use web_net::{App, post};
    ///
    /// let app = App::builder()
    ///     .base("/app")
    ///     .route(post("/contact", |cx| cx.redirect(303, "/thanks")).csrf_exempt("example"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"POST /app/contact HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    /// assert_eq!((r.status, r.header("location")), (303, Some(&b"/app/thanks"[..])));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// 500 `redirect.not_local` when `path` is not a local path (it must
    /// start with one `/`): redirects to other hosts are never built from a
    /// string a handler passes along (use
    /// [`redirect_external`](Self::redirect_external)). 500
    /// `redirect.status` for a status that is not 301, 302, 303, 307, or 308.
    pub fn redirect(&mut self, status: u16, path: &str) -> Result {
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            return Err(Error::internal("redirect.status"));
        }
        if !is_local_target(path) {
            return Err(Error::internal("redirect.not_local"));
        }
        let location = site_url(&self.shared.base, path);
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
    /// ```
    /// use web_net::{App, Context, Guest, Output, Render, RenderError, TemplateId, get};
    ///
    /// struct Page<'a> { title: &'a str }
    /// struct Pages;
    /// impl Render for Pages {
    ///     type View<'a> = Page<'a>;
    ///     fn template(&self, name: &str) -> Option<TemplateId> {
    ///         (name == "page").then_some(TemplateId(0))
    ///     }
    ///     fn render(&self, _: TemplateId, page: &Page<'_>, out: &mut Output<'_>) -> Result<(), RenderError> {
    ///         out.write_str(page.title) // a real engine escapes
    ///     }
    /// }
    ///
    /// let app = App::builder()
    ///     .render(Pages)
    ///     .route(get("/", |cx: &mut Context<'_, Guest, Pages>| cx.render(&Page { title: "Home" })).template("page"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "Home");
    /// assert_eq!(r.header("content-type"), Some(&b"text/html; charset=utf-8"[..]));
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// 500 `render.no_engine` or `render.no_template` when nothing can
    /// render; the engine's own [`RenderError`](crate::RenderError) as a 500;
    /// a checkpoint's denial.
    pub fn render(&mut self, view: &E::View<'_>) -> Result {
        let t = self
            .template
            .ok_or_else(|| Error::internal("render.no_template"))?;
        self.render_id(t, view)
    }

    /// Renders the template `name` against `view`. The name is resolved by
    /// the engine on every call; prefer [`render`](Self::render) with a
    /// template declared on the route, resolved once at build.
    ///
    /// ```
    /// use web_net::{App, Context, Guest, Output, Render, RenderError, TemplateId, get};
    ///
    /// struct Page<'a> { title: &'a str }
    /// struct Pages;
    /// impl Render for Pages {
    ///     type View<'a> = Page<'a>;
    ///     fn template(&self, name: &str) -> Option<TemplateId> {
    ///         (name == "page").then_some(TemplateId(0))
    ///     }
    ///     fn render(&self, _: TemplateId, page: &Page<'_>, out: &mut Output<'_>) -> Result<(), RenderError> {
    ///         out.write_str(page.title) // a real engine escapes
    ///     }
    /// }
    ///
    /// let app = App::builder()
    ///     .render(Pages)
    ///     .route(get("/", |cx: &mut Context<'_, Guest, Pages>| cx.render_named("page", &Page { title: "Named" })))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "Named");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`render`](Self::render).
    pub fn render_named(&mut self, name: &str, view: &E::View<'_>) -> Result {
        let engine = self
            .shared
            .render
            .as_ref()
            .ok_or_else(|| Error::internal("render.no_engine"))?;
        let t = engine
            .template(name)
            .ok_or_else(|| Error::internal("render.no_template"))?;
        self.render_id(t, view)
    }

    fn render_id(&mut self, t: TemplateId, view: &E::View<'_>) -> Result {
        let engine = self
            .shared
            .render
            .as_ref()
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
                Verdict::Deny { status } => {
                    // As at the authorized stage: an error status, or 403.
                    let status = if (400..=599).contains(&status) {
                        status
                    } else {
                        403
                    };
                    return Err(Error::new(status, "checkpoint.denied"));
                }
                _ => return Err(Error::forbidden("checkpoint.killed")),
            }
        }
        self.out.body.clear();
        let mut output = Output::new(&mut self.out.body, self.shared.page_limit);
        let rendered = engine.render(t, view, &mut output);
        let over = output.over();
        if let Err(e) = rendered {
            self.out.body.clear();
            return Err(e.into());
        }
        if over {
            self.out.body.clear();
            return Err(crate::RenderError::new("render.too_large").into());
        }
        self.content_type("text/html; charset=utf-8");
        Ok(())
    }
}

impl<I, E> Context<'_, I, E>
where
    E: for<'a> Render<View<'a> = dyn View + 'a>,
{
    /// [`render`](Self::render) for an engine that reads any [`View`] (a
    /// dynamic engine): takes `&dyn View`, so a [`Fields`](crate::Fields)
    /// or any view of yours goes in as it is.
    ///
    /// ```
    /// use web_net::{App, Fields, Output, Render, RenderError, TemplateId, Value, View, get};
    ///
    /// /// Writes the view's `title` field.
    /// struct Echo;
    /// impl Render for Echo {
    ///     type View<'a> = dyn View + 'a;
    ///     fn template(&self, _: &str) -> Option<TemplateId> { Some(TemplateId(0)) }
    ///     fn render(&self, _: TemplateId, view: &dyn View, out: &mut Output<'_>) -> Result<(), RenderError> {
    ///         let key = view.shape().key("title").ok_or(RenderError::new("echo.no_title"))?;
    ///         out.write_str(view.get(key).as_text().unwrap_or("")) // a real engine escapes
    ///     }
    /// }
    ///
    /// let app = App::builder()
    ///     .render(Echo)
    ///     .route(get("/", |cx| cx.render_view(&Fields(&[("title", Value::Text("Home"))]))).template("page"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "Home");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`render`](Self::render).
    pub fn render_view(&mut self, view: &dyn View) -> Result {
        self.render(view)
    }

    /// [`render_named`](Self::render_named) for an engine that reads any
    /// [`View`].
    ///
    /// ```
    /// use web_net::{App, Fields, Output, Render, RenderError, TemplateId, Value, View, get};
    ///
    /// /// Writes the view's `title` field.
    /// struct Echo;
    /// impl Render for Echo {
    ///     type View<'a> = dyn View + 'a;
    ///     fn template(&self, _: &str) -> Option<TemplateId> { Some(TemplateId(0)) }
    ///     fn render(&self, _: TemplateId, view: &dyn View, out: &mut Output<'_>) -> Result<(), RenderError> {
    ///         let key = view.shape().key("title").ok_or(RenderError::new("echo.no_title"))?;
    ///         out.write_str(view.get(key).as_text().unwrap_or("")) // a real engine escapes
    ///     }
    /// }
    ///
    /// let app = App::builder()
    ///     .render(Echo)
    ///     .route(get("/", |cx| cx.render_view_named("page", &Fields(&[("title", Value::Text("Named"))]))))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "Named");
    /// # Ok::<(), web_net::BuildError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`render`](Self::render).
    pub fn render_view_named(&mut self, name: &str, view: &dyn View) -> Result {
        self.render_named(name, view)
    }
}

impl<I, E: Render> fmt::Debug for Context<'_, I, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
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
