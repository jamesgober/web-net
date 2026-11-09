# web-net - API Reference

> Every public item in `web-net`, with examples. Version `0.7.0`.
> Design and reasons: [`../dev/PLAN.md`](../dev/PLAN.md).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Quick start](#quick-start)
- [`App` and `Builder`](#app-and-builder)
- [Routes and groups](#routes-and-groups)
- [`Cx`: the handler context](#cx-the-handler-context)
- [Gates](#gates)
- [`Request`](#request)
- [Hooks](#hooks)
- [Rendering](#rendering)
- [Errors](#errors)
- [Static files and health](#static-files-and-health)
- [Security headers](#security-headers)
- [Forms, uploads, CSRF](#forms-uploads-csrf)
- [CORS, caching, compression, sites](#cors-caching-compression-sites)
- [Events and checkpoints](#events-and-checkpoints)
- [URL rules](#url-rules)
- [Constants](#constants)

## Quick start

```rust
use web_net::{App, get};

let app = App::builder()
    .route(get("/", |cx| { cx.html(200, "<h1>Hello</h1>"); Ok(()) }).public())
    .build()?;

// On a server:
// serve_net::Server::builder()
//     .listener(serve_net::ListenerSpec::tcp("web", "127.0.0.1:8080"))
//     .serve(app)?
//     .wait();

// In a test, no socket:
let reply = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
assert_eq!(reply.status, 200);
# Ok::<(), web_net::BuildError>(())
```

## `App` and `Builder`

```rust
pub struct App<G: Gate = Open>;
impl App<Open> { pub fn builder() -> Builder<Open>; }
impl<G: Gate> App<G> {
    pub fn with_gate(gate: G) -> Builder<G>;
    pub fn respond(&self, req: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome;
    pub fn respond_identified(&self, req: &HttpRequest<'_>, env: &Envelope, who: &G::Identity, reply: &mut HttpReply) -> Outcome;
    pub fn serve(&self, req: &HttpRequest<'_>, env: &Envelope, who: Option<&G::Identity>, reply: &mut HttpReply) -> Served;
    pub fn classify(&self, head: &HttpHead<'_>) -> Classified;
    pub fn gate(&self) -> &G;
}
impl<G: Gate> serve_net::HttpService for App<G>;
```

- `respond` runs the whole pipeline, authentication included. `HttpService::call` is `respond`.
- `respond_identified` takes the identity from a caller that authenticated already; authorization still runs per route.
- `classify` (for a wrapper's `HttpService::head`) returns `Classified { route: Option<RouteId>, work: WorkClass }` without answering or calling the gate. A request that will be redirected or refused classifies as no route.

`Builder<G>` methods (all return `Self` except `build`):

| Method | Effect |
|---|---|
| `route(Route)` | adds a route |
| `group(Group)` | adds a group's routes |
| `hook(Hook, Routes, f)` | runs `f` at the hook for the selected routes |
| `host(&str)` | a host the site answers; the first is canonical; none declared = any host |
| `alias(&str)` | a host redirected to the canonical one |
| `development()` | `localhost`, `127.0.0.1`, `[::1]`, `*.localhost` are the site; no HTTPS needed for them |
| `base(&str)` | the folder the site is installed under (`/blog`) |
| `trailing_slash(TrailingSlash)` | `Strip` (default), `Add`, `Ignore` |
| `lowercase_paths()` | upper-case paths are redirected |
| `https_only()` | plain HTTP redirected to HTTPS on the canonical host (needs a host) |
| `sign_in(&str)` | the page a `Denial::sign_in` on `GET`/`HEAD` redirects to (303, with `next`) |
| `challenge(&str)` | `WWW-Authenticate` for a 401 (default `Session`) |
| `render(impl Render)` | the template engine |
| `events(impl Events)` | where refusals, denials, and failures go |
| `checkpoint(impl Checkpoint)` | in-flight revocation at web-net's stages |
| `page_limit(usize)` | budget for one rendered page (default `DEFAULT_PAGE_LIMIT`, 8 MiB) |
| `wipe_buffers()` | zero the reused reply buffers after every request |
| `assets(Assets)` | a folder served under a mount, before the gate |
| `health(&str)` | a liveness path (`200 ok`) |
| `ready(&str, Fn() -> bool)` | a readiness path (`200 ready` / `503 not ready`) |
| `security_headers(SecurityHeaders)` | the security headers on every reply |
| `csrf(csrf_sec::Csrf)` | CSRF protection (required when a route takes an unsafe method and is not exempt) |
| `redirect_hosts(&[&str])` | hosts `Cx::redirect_external` may send to |
| `compress(Compression)` | gzip for compressible replies |
| `build()` | `Result<App<G>, BuildError>` with every problem listed |

## Routes and groups

```rust
pub fn get<I, R, F>(pattern: impl Into<String>, f: F) -> Route<I, R>;  // also post, put, patch, delete
impl<I, R> Route<I, R> {
    pub fn at(pattern: impl Into<String>) -> Self;
    pub fn on(self, method: Method, handler: impl Handler<I>) -> Self;
    pub fn get(self, f) -> Self;   // also post, put, patch, delete
    pub fn public(self) -> Self;
    pub fn allow(self, rule: R) -> Self;
    pub fn name(self, name: &'static str) -> Self;
    pub fn work(self, work: WorkClass) -> Self;
    pub fn template(self, name: &'static str) -> Self;
    pub fn csrf_exempt(self, reason: &'static str) -> Self;
    pub fn form_limits(self, limits: form_net::Limits) -> Self;
    pub fn cors(self, cors: Cors) -> Self;
    pub fn cache(self, policy: CachePolicy) -> Self;
}
impl<I, R> Group<I, R> {
    pub fn new(prefix: impl Into<String>) -> Self;
    pub fn public(self) -> Self;
    pub fn allow(self, rule: R) -> Self;
    pub fn route(self, route: Route<I, R>) -> Self;
    pub fn group(self, group: Group<I, R>) -> Self;
    pub fn cors(self, cors: Cors) -> Self;
    pub fn cache(self, policy: CachePolicy) -> Self;
}
pub trait Handler<I>: Send + Sync + 'static { fn call(&self, cx: &mut Cx<'_, I>) -> Result; }
```

Patterns: `/users/:id/files/*rest`. Literals are written decoded (`/café`). At most `MAX_PARAMS` (8) parameters. A route needs `.public()` or `.allow(rule)` (from itself or its group).

A closure that reads fields of a custom identity needs its parameter typed, because the closure is checked before the builder fixes the type:

```rust
# use web_net::{Cx, get, Route};
# struct User { name: String }
# impl web_net::Identity for User { fn is_guest(&self) -> bool { false } }
# enum Rule { SignedIn }
let account: Route<User, Rule> = get("/account", |cx: &mut Cx<'_, User>| {
    let name = cx.identity().name.clone();
    cx.text(200, &name);
    Ok(())
})
.allow(Rule::SignedIn);
```

Named functions (`fn account(cx: &mut Cx<'_, User>) -> web_net::Result`) need nothing extra.

## `Cx`: the handler context

| Read | |
|---|---|
| `request() -> &Request` | the request |
| `method()`, `path()`, `header(name)` | shortcuts |
| `identity() -> &I` | who is asking (possibly a guest) |
| `id() -> RequestId` | the reference shown on error pages |
| `param(name) -> Option<Cow<str>>` | a route parameter, decoded |
| `param_as::<T>(name) -> Result<T>` | parsed; 404 `route.param` when it does not parse |
| `query(name) -> Result<Option<Cow<str>>>` | decoded; 400 `query.duplicate` for a repeated name |
| `body() -> Result<&[u8]>` | the raw body (on an unsafe method, its CSRF token was checked before the handler) |
| `body_mut() -> &mut Vec<u8>` | the reply body buffer, emptied, for an engine that writes into a `Vec<u8>` |
| `form::<T>() -> Result<T, FormError>` | a typed form, the token checked in the same pass |
| `form_inspected::<T, N>(&mut N)` | the same with an inspector |
| `upload(&Store) -> Result<Upload, FormError>` | an upload (feature `uploads`); `upload_inspected` |
| `csrf_token() -> Result<String>` | a token for the visitor's binding |
| `precondition(tag, modified) -> Result` | 412 when `If-Match` or `If-Unmodified-Since` is false |

| Write | |
|---|---|
| `status(u16)` | default 200 |
| `set_header(name, value)` | checked; a bad field or a framing field makes the reply a 500 |
| `body_bytes(&[u8])`, `html(status, &str)`, `text(status, &str)` | the body |
| `url(path) -> String` | the base path in front |
| `language(offers) -> Option<&str>` | the best `Accept-Language` match |
| `media(offers) -> Option<&str>` | the best `Accept` match |
| `see_other(path) -> Result` | 303 to a site-relative path |
| `redirect(status, path) -> Result` | 301, 302, 303, 307, 308 to a site-relative path |
| `redirect_external(status, url) -> Result` | to a host from `redirect_hosts` only |
| `render(&dyn View) -> Result` | the route's template |
| `render_named(name, &dyn View) -> Result` | a template by name |
| `set_cookie(&cookie_net::SetCookie)` | a `Set-Cookie` field |
| `not_modified(tag) -> bool` | sets `ETag`; `true` (and 304) when `If-None-Match` matches |

The reply is held by web-net until the handler returns; on an error or a panic it is discarded and the error page is sent instead.

## Gates

```rust
pub trait Identity: Send + Sync + 'static {
    fn is_guest(&self) -> bool;
    fn csrf_binding(&self) -> Option<&[u8]> { None }
    fn set_cookie(&self) -> Option<&str> { None }   // written on every exit of respond
}
pub trait Gate: Send + Sync + 'static {
    type Identity: Identity;
    type Rule: Send + Sync + 'static;
    fn authenticate(&self, req: &Request<'_>) -> Result<Self::Identity, Denial>;
    fn authorize(&self, who: &Self::Identity, rule: &Self::Rule, req: &Request<'_>) -> Result<(), Denial>;
}
pub struct Open;   // Identity = Guest, Rule = NoRule (no values)
pub struct Guest;
pub enum NoRule {}

pub struct Denial;
impl Denial {
    pub const fn sign_in(code: &'static str) -> Self;     // 303 to sign-in for GET/HEAD, else 401
    pub const fn forbidden(code: &'static str) -> Self;   // 403
    pub const fn hidden(code: &'static str) -> Self;      // 404
    pub const fn status(status: u16, code: &'static str) -> Self; // 4xx; anything else is 403
    pub const fn kind(&self) -> DenialKind;
    pub const fn code(&self) -> &'static str;
    pub const fn status_code(&self) -> u16;
    pub fn with_cookie(self, set_cookie: impl Into<Box<str>>) -> Self;
    pub fn cookie(&self) -> Option<&str>;
}
pub enum DenialKind { SignIn, Forbidden, Hidden, Status(u16) }
```

## `Request`

What gates and handlers read: `method()`, `path()` (canonical, inside the site), `query()`, `host()`, `header(name)`, `header_str(name)`, `cookie(name) -> Result<Option<&str>, Ambiguous>`, `client()`, `scheme()`, `route()` (the matched pattern, for `authorize`), `id()`, `envelope()`, `raw()`.

`RequestId` displays as `<connection hex>-<seq>`; `connection()`, `seq()`.

## Hooks

```rust
pub enum Hook { Routed, Finish, BeforeRender }
impl Routes {
    pub fn all() -> Self;
    pub fn prefix(prefix: impl Into<String>) -> Self;   // segment-aware
    pub fn named(names: &[&'static str]) -> Self;
}
```

`Routed` runs after the access check, before the handler; `Finish` after the handler succeeded. An error from a hook ends the request with its status.

## Rendering

```rust
pub trait Render: Send + Sync + 'static {
    fn template(&self, name: &str) -> Option<TemplateId>;
    fn render(&self, template: TemplateId, view: &dyn View, out: &mut Output<'_>) -> Result<(), RenderError>;
}
pub trait View {
    fn shape(&self) -> &dyn Shape;
    fn get(&self, key: Key) -> Value<'_>;
    fn call(&self, key: Key, args: &[Value<'_>], with: &mut dyn FnMut(Value<'_>)) { /* Absent */ }
}
pub trait Shape { fn id(&self) -> ShapeId; fn key(&self, name: &str) -> Option<Key>; }
pub trait List { fn len(&self) -> usize; fn is_empty(&self) -> bool; fn get(&self, index: usize) -> Value<'_>; }
pub enum Value<'a> { Absent, Bool(bool), Int(i64), Float(f64), Text(&'a str), Html(SafeHtml<'a>),
                     Display(&'a dyn Display), View(&'a dyn View), List(&'a dyn List) }
pub struct SafeHtml<'a>;      // SafeHtml::trusted(&str), as_str()
pub struct Fields<'a>(pub &'a [(&'a str, Value<'a>)]);   // a ready-made view, anonymous shape
pub struct Output<'a>;        // new(&mut Vec<u8>, limit), write, write_str, len, is_empty, remaining
pub struct RenderError;       // new(code), with_detail, code, detail
pub struct TemplateId(pub u32);
pub struct Key(pub u32);
pub struct ShapeId(pub u64);  // ShapeId::ANONYMOUS
```

Error pages render the engine's `error/<status>` template when it has one, with the fields `status`, `title`, `message`, `reference`; otherwise a built-in page.

## Errors

```rust
pub struct Error;
impl Error {
    pub fn new(status: u16, code: &'static str) -> Self;   // 400..=599, else 500
    pub fn bad_request(code) -> Self; pub fn forbidden(code) -> Self; pub fn not_found(code) -> Self;
    pub fn conflict(code) -> Self; pub fn unprocessable(code) -> Self; pub fn internal(code) -> Self;
    pub fn unavailable(code) -> Self;
    pub fn with_source(self, source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self;
    pub fn status(&self) -> u16; pub fn code(&self) -> &'static str;
    pub fn source_ref(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)>;
}
pub type Result<T = (), E = Error> = std::result::Result<T, E>;
pub struct BuildError;    // problems() -> &[Problem]
pub struct Problem { pub subject: String, pub message: String }
```

## Static files and health

```rust
impl Assets {
    pub fn new(mount: &str, dir: impl Into<PathBuf>) -> Self;
    pub fn cache_control(self, value: &str) -> Self;   // default "no-cache"
    pub fn index(self, name: &str) -> Self;             // default none: folders are 404
    pub fn precompressed(self, on: bool) -> Self;       // default on: file.br, file.gz
    pub fn hidden_files(self, on: bool) -> Self;        // default off: .env etc. are 404
}
pub fn mime_for(path: &Path) -> &'static str;
pub const INLINE_LIMIT: u64;   // 1 MiB: larger files go out in parts
```

```rust
use web_net::{App, Assets};

let app = App::builder()
    .assets(Assets::new("/static", "./public").cache_control("public, max-age=31536000, immutable"))
    .health("/healthz")
    .ready("/readyz", || true)
    .build()?;
# Ok::<(), web_net::BuildError>(())
```

Rules (refused segments, validators, ranges, variants): PLAN section 12.1.

## Security headers

```rust
impl SecurityHeaders {
    pub fn none() -> Self;
    pub fn content_security_policy(self, value: &str) -> Self;
    pub fn no_content_security_policy(self) -> Self;
    pub fn frame_options(self, value: &str) -> Self;
    pub fn referrer_policy(self, value: &str) -> Self;
    pub fn permissions_policy(self, value: &str) -> Self;
    pub fn opener_policy(self, value: &str) -> Self;
    pub fn hsts(self, max_age: u64, include_subdomains: bool) -> Self;
    pub fn no_hsts(self) -> Self;
}
impl Default for SecurityHeaders;   // the strict defaults in PLAN section 12.2
pub const DEFAULT_CSP: &str;
```

## Forms, uploads, CSRF

```rust
use web_net::form_net::{self, FromForm};
use web_net::{App, Cx, csrf_sec::Csrf, post};
# struct Visitor; impl web_net::Identity for Visitor { fn is_guest(&self) -> bool { false } fn csrf_binding(&self) -> Option<&[u8]> { Some(b"session-id") } }
# struct G; impl web_net::Gate for G { type Identity = Visitor; type Rule = ();
#   fn authenticate(&self, _: &web_net::Request<'_>) -> Result<Visitor, web_net::Denial> { Ok(Visitor) }
#   fn authorize(&self, _: &Visitor, _: &(), _: &web_net::Request<'_>) -> Result<(), web_net::Denial> { Ok(()) } }

form_net::form! {
    pub struct Email { pub email: String }
    ignore = ["csrf_token"];
}

let app = App::with_gate(G)
    .csrf(Csrf::new(*b"a persisted 32-byte secret key!!").unwrap())
    .route(post("/account/email", |cx: &mut Cx<'_, Visitor>| {
        match cx.form::<Email>() {
            Ok(form) => { let _ = form.email; cx.see_other("/account") }
            Err(e) if e.status_hint() == 422 => { cx.html(422, "<p>check the form</p>"); Ok(()) }
            Err(e) => Err(e.into()),
        }
    }).public())
    .build()?;
# Ok::<(), web_net::BuildError>(())
```

The rules (binding, origin policy, where the token may come from, what is refused): PLAN section 12.3. Codes: `csrf.no_binding`, `csrf.missing`, `csrf.duplicate`, `csrf.unreadable_form`, `csrf.no_engine`, and csrf-sec's reasons as `csrf.<reason>` (`csrf.bad_mac`, `csrf.cross_site`, ...).

## CORS, caching, compression, sites

```rust
impl Cors {
    pub fn new() -> Self; pub fn origin(self, origin: &str) -> Self; pub fn any_origin(self) -> Self;
    pub fn headers(self, names: &[&str]) -> Self; pub fn expose(self, names: &[&str]) -> Self;
    pub fn credentials(self) -> Self; pub fn max_age(self, seconds: u32) -> Self;
}
pub enum CachePolicy { Unset, NoStore, Private { max_age: u32 }, Public { max_age: u32 }, Guests { max_age: u32 } }
pub enum Cacheable { No, Guests { max_age: u32 } }
pub struct Served { pub outcome: Outcome, pub route: Option<RouteId>, pub cache: Cacheable }
impl Compression { pub fn min_bytes(self, bytes: usize) -> Self; pub fn level(self, level: u8) -> Self; }   // Default: 1024 bytes, level 6
impl<G: Gate> Sites<G> {
    pub fn new() -> Self; pub fn site(self, app: App<G>) -> Self;
    pub fn pick(&self, req: &HttpRequest<'_>) -> Option<&App<G>>;
    pub fn serve(&self, req, env, who: Option<&G::Identity>, reply) -> Served;
}
impl<G: Gate> serve_net::HttpService for Sites<G>;
```

Rules: PLAN sections 12, 12.4, 12.5.

## Events and checkpoints

```rust
pub trait Events: Send + Sync + 'static { fn event(&self, event: &Event<'_>) {} }
pub struct NoEvents;
pub struct Event<'a> { pub kind: EventKind, pub id: RequestId, pub route: Option<&'a str>,
                       pub status: u16, pub code: &'static str,
                       pub source: Option<&'a (dyn std::error::Error + 'static)> }
pub enum EventKind { Refused, Denied, Failed, Panicked, Revoked }

pub trait Checkpoint: Send + Sync + 'static { fn check(&self, env: &Envelope, at: Stage) -> serve_net::Verdict; }
pub enum Stage { Authorized, BeforeRender }
```

Codes web-net reports: `url.not_absolute`, `url.bad_escape`, `url.encoded_slash`, `url.backslash`, `url.control`, `url.not_utf8`, `url.too_many_segments`, `url.asterisk`, `host.unknown`, `site.outside_base`, `route.none`, `assets.none`, `cors.denied`, `method.not_allowed`, `method.unknown`, `checkpoint.denied`, `checkpoint.killed`, `reply.invalid_field`, `handler.panic`, plus the gates' and handlers' own codes.

## URL rules

`UrlError` (`code()`, `Display`): `NotAbsolute`, `BadEscape`, `EncodedSlash`, `Backslash`, `Control`, `NotUtf8`, `TooManySegments`. `TrailingSlash`: `Strip`, `Add`, `Ignore`. The rules are in PLAN section 4.

## Constants

- `VERSION: &str`: the crate version.
- `MAX_PARAMS: usize = 8`: parameters per route pattern.
- `DEFAULT_PAGE_LIMIT: usize = 8 MiB`: the default page budget.
- `INLINE_LIMIT: u64 = 1 MiB`: files up to this size are read whole.
- `DEFAULT_CSP: &str`: the default content security policy.
- `cookie_net`, `csrf_sec`, `form_net`: the crates, re-exported.
